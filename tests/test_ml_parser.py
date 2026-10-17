"""Unit tests for the LexiBOM AI/ML Model Weight & Artifact Parser."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from lexibom.parsers.base import ComponentType
from lexibom.parsers.ml_model_parser import MLModelParser, resolve_model_license


def create_mock_safetensors(
    target_path: Path, metadata: dict[str, str], trailing_tensor_bytes: bytes = b"\x00" * 128
) -> Path:
    """Create a binary .safetensors file with an 8-byte header length and JSON header."""
    header_obj = {
        "__metadata__": metadata,
        "weight_matrix": {
            "dtype": "F16",
            "shape": [8, 8],
            "data_offsets": [0, len(trailing_tensor_bytes)],
        },
    }
    header_bytes = json.dumps(header_obj).encode("utf-8")
    prefix = struct.pack("<Q", len(header_bytes))
    target_path.write_bytes(prefix + header_bytes + trailing_tensor_bytes)
    return target_path


def test_known_model_license_cache() -> None:
    """Verify local license resolution for canonical Hugging Face model IDs."""
    raw_llama, norm_llama, _ = resolve_model_license("meta-llama/Llama-3-8B")
    assert raw_llama == "Llama-3-Community"
    assert norm_llama == "Llama-3-Community"

    raw_sdxl, norm_sdxl, _ = resolve_model_license(
        "stabilityai/stable-diffusion-xl-base-1.0"
    )
    assert raw_sdxl == "CreativeML OpenRAIL-M"
    assert norm_sdxl == "OpenRAIL-M"

    raw_mistral, norm_mistral, _ = resolve_model_license("mistralai/Mistral-7B-v0.1")
    assert raw_mistral == "Apache-2.0"
    assert norm_mistral == "Apache-2.0"

    raw_vicuna, norm_vicuna, _ = resolve_model_license("lmsys/vicuna-13b-v1.5")
    assert raw_vicuna == "CC-BY-NC-4.0"
    assert norm_vicuna == "CC-BY-NC-4.0"


def test_parse_safetensors_header_without_loading_tensors(tmp_path: Path) -> None:
    """Ensure .safetensors binary headers are parsed accurately for embedded license metadata."""
    sf_file = create_mock_safetensors(
        tmp_path / "sdxl_lora.safetensors",
        metadata={
            "model_id": "stabilityai/stable-diffusion-xl-base-1.0",
            "license": "CreativeML OpenRAIL-M",
            "version": "1.0.0",
            "author": "Stability AI",
        },
        trailing_tensor_bytes=b"\xff" * 4096,
    )

    header = MLModelParser.read_safetensors_header(sf_file)
    assert header["__metadata__"]["license"] == "CreativeML OpenRAIL-M"

    parser = MLModelParser()
    components = parser.parse_file(sf_file, project_root=tmp_path)
    assert len(components) == 1
    comp = components[0]
    assert comp.name == "stabilityai/stable-diffusion-xl-base-1.0"
    assert comp.component_type == ComponentType.ML_MODEL
    assert comp.raw_license == "CreativeML OpenRAIL-M"
    assert comp.normalized_license == "OpenRAIL-M"
    assert comp.source_file == "sdxl_lora.safetensors"


def test_corrupted_safetensors_file_handled_gracefully(tmp_path: Path) -> None:
    """Verify truncated or corrupted .safetensors files raise ValueError in read_safetensors_header and do not crash scan."""
    bad_file = tmp_path / "corrupt.safetensors"
    bad_file.write_bytes(b"short")

    with pytest.raises(ValueError, match="smaller than 8 bytes"):
        MLModelParser.read_safetensors_header(bad_file)

    parser = MLModelParser()
    assert parser.parse_file(bad_file) == []


def test_parse_huggingface_config_manifests_does_not_conflate_transformers_version(
    tmp_path: Path,
) -> None:
    """Test extraction from config.json and model_index.json without misattributing transformers_version as model version."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "_name_or_path": "meta-llama/Llama-3-8B",
                "architectures": ["LlamaForCausalLM"],
                "transformers_version": "4.40.0",
            }
        ),
        encoding="utf-8",
    )

    model_index = tmp_path / "model_index.json"
    model_index.write_text(
        json.dumps(
            {
                "_class_name": "StableDiffusionXLPipeline",
                "_name_or_path": "stabilityai/stable-diffusion-xl-base-1.0",
                "_diffusers_version": "0.27.0",
                "version": "1.0",
            }
        ),
        encoding="utf-8",
    )

    parser = MLModelParser()
    c1 = parser.parse_file(config_file, project_root=tmp_path)
    assert len(c1) == 1
    assert c1[0].name == "meta-llama/Llama-3-8B"
    assert c1[0].version == "main"
    assert c1[0].metadata["transformers_version"] == "4.40.0"
    assert c1[0].normalized_license == "Llama-3-Community"

    c2 = parser.parse_file(model_index, project_root=tmp_path)
    assert len(c2) == 1
    assert c2[0].name == "stabilityai/stable-diffusion-xl-base-1.0"
    assert c2[0].version == "1.0"
    assert c2[0].metadata["diffusers_version"] == "0.27.0"
    assert c2[0].normalized_license == "OpenRAIL-M"


def test_detect_declared_models_in_python_code_and_ignore_comments(
    tmp_path: Path,
) -> None:
    """Verify AST scanner detects active from_pretrained/pipeline calls, resolves constants, and ignores comments/docstrings."""
    py_file = tmp_path / "pipeline_runner.py"
    py_file.write_text(
        '''
"""
Example docstring that should be ignored:
AutoModel.from_pretrained("stanford-crfm/alpaca-7b")
"""
from transformers import AutoModel, AutoModelForCausalLM, pipeline
from diffusers import DiffusionPipeline

# Commented-out model that must NOT be flagged:
# bad_model = AutoModel.from_pretrained("lmsys/vicuna-7b-v1.5")

DEFAULT_LLM = "meta-llama/Llama-3-8B"

m1 = AutoModel.from_pretrained("mistralai/Mistral-7B-v0.1")
m2 = AutoModelForCausalLM.from_pretrained(DEFAULT_LLM)
pipe = DiffusionPipeline.from_pretrained("stabilityai/stable-diffusion-xl-base-1.0")
clf = pipeline("text-generation", model="lmsys/vicuna-13b-v1.5")
''',
        encoding="utf-8",
    )

    env_file = tmp_path / ".env"
    env_file.write_text("HF_MODEL_ID=google/gemma-7b\n", encoding="utf-8")

    parser = MLModelParser()
    py_comps = parser.parse_file(py_file, project_root=tmp_path)
    by_name = {c.name: c for c in py_comps}

    assert "stanford-crfm/alpaca-7b" not in by_name
    assert "lmsys/vicuna-7b-v1.5" not in by_name

    assert "mistralai/Mistral-7B-v0.1" in by_name
    assert by_name["mistralai/Mistral-7B-v0.1"].normalized_license == "Apache-2.0"

    assert "meta-llama/Llama-3-8B" in by_name
    assert by_name["meta-llama/Llama-3-8B"].normalized_license == "Llama-3-Community"

    assert "stabilityai/stable-diffusion-xl-base-1.0" in by_name
    assert by_name["stabilityai/stable-diffusion-xl-base-1.0"].normalized_license == "OpenRAIL-M"

    assert "lmsys/vicuna-13b-v1.5" in by_name
    assert by_name["lmsys/vicuna-13b-v1.5"].normalized_license == "CC-BY-NC-4.0"

    env_comps = parser.parse_file(env_file, project_root=tmp_path)
    assert len(env_comps) == 1
    assert env_comps[0].name == "google/gemma-7b"
    assert env_comps[0].normalized_license == "Gemma-Terms-of-Use"
