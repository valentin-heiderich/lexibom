"""Parser for AI/ML model artifacts (.safetensors headers, Hugging Face manifests, and code references)."""

from __future__ import annotations

import ast
import json
import re
import struct
from pathlib import Path
from typing import Any

from lexibom.legal.taxonomy import normalize_license
from lexibom.parsers.base import BaseParser, ComponentType, DiscoveredComponent

MAX_SAFETENSORS_HEADER_BYTES = 64 * 1024 * 1024  # 64 MB safety cap

# Local cache of known Hugging Face / ML model licenses:
# Maps lowercase repo_id -> (canonical_repo_id, raw_license, copyright_holder)
KNOWN_MODEL_LICENSES: dict[str, tuple[str, str, str]] = {
    "meta-llama/llama-3-8b": (
        "meta-llama/Llama-3-8B",
        "Llama-3-Community",
        "Meta Platforms, Inc.",
    ),
    "meta-llama/llama-3-8b-instruct": (
        "meta-llama/Llama-3-8B-Instruct",
        "Llama-3-Community",
        "Meta Platforms, Inc.",
    ),
    "meta-llama/llama-3-70b": (
        "meta-llama/Llama-3-70B",
        "Llama-3-Community",
        "Meta Platforms, Inc.",
    ),
    "meta-llama/meta-llama-3-8b": (
        "meta-llama/Meta-Llama-3-8B",
        "Llama-3-Community",
        "Meta Platforms, Inc.",
    ),
    "meta-llama/llama-2-7b-hf": (
        "meta-llama/Llama-2-7b-hf",
        "Llama-2-Community",
        "Meta Platforms, Inc.",
    ),
    "meta-llama/llama-2-13b-hf": (
        "meta-llama/Llama-2-13b-hf",
        "Llama-2-Community",
        "Meta Platforms, Inc.",
    ),
    "stabilityai/stable-diffusion-xl-base-1.0": (
        "stabilityai/stable-diffusion-xl-base-1.0",
        "CreativeML OpenRAIL-M",
        "Stability AI Ltd.",
    ),
    "stabilityai/stable-diffusion-2-1": (
        "stabilityai/stable-diffusion-2-1",
        "CreativeML OpenRAIL-M",
        "Stability AI Ltd.",
    ),
    "runwayml/stable-diffusion-v1-5": (
        "runwayml/stable-diffusion-v1-5",
        "CreativeML OpenRAIL-M",
        "Runway ML / CompVis",
    ),
    "compvis/stable-diffusion-v1-4": (
        "CompVis/stable-diffusion-v1-4",
        "CreativeML OpenRAIL-M",
        "CompVis / LMU Munich",
    ),
    "bigscience/bloom": (
        "bigscience/bloom",
        "BigScience-OpenRAIL-M",
        "BigScience Workshop",
    ),
    "mistralai/mistral-7b-v0.1": (
        "mistralai/Mistral-7B-v0.1",
        "Apache-2.0",
        "Mistral AI",
    ),
    "mistralai/mistral-7b-instruct-v0.2": (
        "mistralai/Mistral-7B-Instruct-v0.2",
        "Apache-2.0",
        "Mistral AI",
    ),
    "mistralai/mixtral-8x7b-v0.1": (
        "mistralai/Mixtral-8x7B-v0.1",
        "Apache-2.0",
        "Mistral AI",
    ),
    "lmsys/vicuna-13b-v1.5": (
        "lmsys/vicuna-13b-v1.5",
        "CC-BY-NC-4.0",
        "Large Model Systems Organization (LMSYS)",
    ),
    "lmsys/vicuna-7b-v1.5": (
        "lmsys/vicuna-7b-v1.5",
        "CC-BY-NC-4.0",
        "Large Model Systems Organization (LMSYS)",
    ),
    "stanford-crfm/alpaca-7b": (
        "stanford-crfm/alpaca-7b",
        "CC-BY-NC-4.0",
        "Stanford Center for Research on Foundation Models",
    ),
    "google/gemma-7b": (
        "google/gemma-7b",
        "Gemma-Terms-of-Use",
        "Google LLC",
    ),
    "google/gemma-2b": (
        "google/gemma-2b",
        "Gemma-Terms-of-Use",
        "Google LLC",
    ),
    "openai/whisper-large-v3": (
        "openai/whisper-large-v3",
        "MIT",
        "OpenAI",
    ),
    "baai/bge-large-en-v1.5": (
        "BAAI/bge-large-en-v1.5",
        "MIT",
        "Beijing Academy of Artificial Intelligence (BAAI)",
    ),
    "qwen/qwen2.5-7b": (
        "Qwen/Qwen2.5-7B",
        "Apache-2.0",
        "Alibaba Cloud / Qwen Team",
    ),
    "bert-base-uncased": (
        "bert-base-uncased",
        "Apache-2.0",
        "Google Research",
    ),
    "gpt2": (
        "gpt2",
        "MIT",
        "OpenAI",
    ),
}

_MANIFEST_FILENAMES: frozenset[str] = frozenset(
    {
        "config.json",
        "model_index.json",
        "model_config.json",
        "adapter_config.json",
        "model_manifest.json",
    }
)

# Regex patterns for detecting model references in code and environment files
_FROM_PRETRAINED_RE = re.compile(
    r"""(?:\b[A-Za-z0-9_]*Model[A-Za-z0-9_]*|\bAuto[A-Za-z0-9_]+|\b[A-Za-z0-9_]*Pipeline[A-Za-z0-9_]*|\b[A-Za-z0-9_]*Tokenizer[A-Za-z0-9_]*)\.from_pretrained\(\s*(?:pretrained_model_name_or_path\s*=\s*)?['"]([^'"]+)['"]"""
)
_PIPELINE_MODEL_RE = re.compile(
    r"""\bpipeline\(\s*['"][^'"]+['"]\s*,\s*(?:model\s*=\s*)?['"]([^'"]+)['"]"""
)
_HF_HUB_DOWNLOAD_RE = re.compile(
    r"""\b(?:snapshot_download|hf_hub_download)\(\s*(?:repo_id\s*=\s*)?['"]([^'"]+)['"]"""
)
_SENTENCE_TRANSFORMER_RE = re.compile(
    r"""\bSentenceTransformer\(\s*(?:model_name_or_path\s*=\s*)?['"]([^'"]+)['"]"""
)
_ENV_MODEL_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:HF_MODEL_ID|MODEL_ID|MODEL_NAME_OR_PATH|BASE_MODEL_ID)\s*=\s*['"]?([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)['"]?\s*$""",
    re.MULTILINE,
)


def resolve_model_license(
    model_id: str, explicit_license: str | None = None
) -> tuple[str, str, str]:
    """Resolve (raw_license, normalized_license, copyright_holder) for a model identifier."""
    lowered = model_id.strip().lower()
    holder = "Model Authors and Contributors"
    if lowered in KNOWN_MODEL_LICENSES:
        _, known_raw, holder = KNOWN_MODEL_LICENSES[lowered]
        if not explicit_license:
            return known_raw, normalize_license(known_raw), holder

    if explicit_license and explicit_license.strip():
        raw = explicit_license.strip()
        return raw, normalize_license(raw), holder

    # Prefix / pattern heuristics for model families
    if lowered.startswith("meta-llama/llama-3") or lowered.startswith("meta-llama/meta-llama-3"):
        return "Llama-3-Community", "Llama-3-Community", "Meta Platforms, Inc."
    if lowered.startswith("meta-llama/llama-2") or "llama-2" in lowered:
        return "Llama-2-Community", "Llama-2-Community", "Meta Platforms, Inc."
    if lowered.startswith("meta-llama/") or "llama-3" in lowered:
        return "Llama-3-Community", "Llama-3-Community", "Meta Platforms, Inc."
    if "stable-diffusion" in lowered or "openrail" in lowered or lowered.startswith("stabilityai/sdxl"):
        return "CreativeML OpenRAIL-M", "OpenRAIL-M", "Stability AI Ltd."
    if lowered.startswith("mistralai/"):
        return "Apache-2.0", "Apache-2.0", "Mistral AI"
    if lowered.startswith("google/gemma"):
        return "Gemma-Terms-of-Use", "Gemma-Terms-of-Use", "Google LLC"
    if "vicuna" in lowered or "alpaca" in lowered or "cc-by-nc" in lowered or "noncommercial" in lowered:
        return "CC-BY-NC-4.0", "CC-BY-NC-4.0", holder
    if "research-only" in lowered:
        return "NonCommercial-Research-Only", "NonCommercial-Research-Only", holder

    return "UNKNOWN", "UNKNOWN", holder


class _ModelCallVisitor(ast.NodeVisitor):
    """AST visitor that extracts Hugging Face / ML model references from Python calls while ignoring comments/docstrings."""

    def __init__(self) -> None:
        self.constants: dict[str, str] = {}
        self.discovered: list[tuple[str, str]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.constants[target.id] = val
                    if target.id in ("HF_MODEL_ID", "MODEL_ID", "MODEL_NAME_OR_PATH", "BASE_MODEL_ID"):
                        if "/" in val and not val.startswith(".") and not val.startswith("/"):
                            self.discovered.append((val, "env_declaration"))
        self.generic_visit(node)

    def _resolve_str_arg(self, node: ast.expr | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.strip()
        if isinstance(node, ast.Name) and node.id in self.constants:
            return self.constants[node.id]
        return None

    def visit_Call(self, node: ast.Call) -> None:
        # 1. <Class>.from_pretrained(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "from_pretrained":
            repo_id = self._resolve_str_arg(node.args[0]) if node.args else None
            if repo_id is None:
                for kw in node.keywords:
                    if kw.arg in ("pretrained_model_name_or_path", "model_name_or_path", "repo_id"):
                        repo_id = self._resolve_str_arg(kw.value)
                        break
            if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                self.discovered.append((repo_id, "from_pretrained"))

        # 2. pipeline("task", model="...") or snapshot_download(...) / hf_hub_download(...) / SentenceTransformer(...)
        elif isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn == "pipeline":
                repo_id = self._resolve_str_arg(node.args[1]) if len(node.args) >= 2 else None
                if repo_id is None:
                    for kw in node.keywords:
                        if kw.arg == "model":
                            repo_id = self._resolve_str_arg(kw.value)
                            break
                if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                    self.discovered.append((repo_id, "transformers_pipeline"))
            elif fn in ("snapshot_download", "hf_hub_download"):
                repo_id = self._resolve_str_arg(node.args[0]) if node.args else None
                if repo_id is None:
                    for kw in node.keywords:
                        if kw.arg == "repo_id":
                            repo_id = self._resolve_str_arg(kw.value)
                            break
                if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                    self.discovered.append((repo_id, "hf_hub_download"))
            elif fn == "SentenceTransformer":
                repo_id = self._resolve_str_arg(node.args[0]) if node.args else None
                if repo_id is None:
                    for kw in node.keywords:
                        if kw.arg == "model_name_or_path":
                            repo_id = self._resolve_str_arg(kw.value)
                            break
                if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                    self.discovered.append((repo_id, "sentence_transformer"))

        self.generic_visit(node)


class MLModelParser(BaseParser):
    """Scans and parses AI/ML model manifests, .safetensors headers, and code references."""

    def __init__(self, custom_license_cache: dict[str, str] | None = None) -> None:
        self.custom_license_cache: dict[str, str] = {
            k.lower(): v for k, v in (custom_license_cache or {}).items()
        }

    def can_parse(self, file_path: Path) -> bool:
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()
        return (
            name in _MANIFEST_FILENAMES
            or suffix == ".safetensors"
            or suffix == ".py"
            or name == ".env"
            or (name.startswith(".env.") and not name.endswith(".example"))
        )

    def parse_file(
        self, file_path: Path, project_root: Path | None = None
    ) -> list[DiscoveredComponent]:
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()
        source_rel = self.format_source_path(file_path, project_root)

        if suffix == ".safetensors":
            comp = self._parse_safetensors_file(file_path, source_rel)
            return [comp] if comp is not None else []
        if name in _MANIFEST_FILENAMES:
            return self._parse_manifest_json(file_path, source_rel)
        if suffix == ".py" or name == ".env" or name.startswith(".env."):
            return self._parse_code_or_env_file(file_path, source_rel)
        return []

    @staticmethod
    def read_safetensors_header(file_path: Path) -> dict[str, Any]:
        """Read only the 8-byte size prefix and JSON header of a .safetensors file without loading tensors."""
        with file_path.open("rb") as fh:
            prefix = fh.read(8)
            if len(prefix) < 8:
                raise ValueError(f"Invalid .safetensors file (smaller than 8 bytes): {file_path}")
            (header_size,) = struct.unpack("<Q", prefix)
            if header_size == 0 or header_size > MAX_SAFETENSORS_HEADER_BYTES:
                raise ValueError(
                    f"Invalid or oversized .safetensors header length ({header_size} bytes) in {file_path}"
                )
            raw_header = fh.read(header_size)
            if len(raw_header) < header_size:
                raise ValueError(
                    f"Truncated .safetensors header in {file_path}: expected {header_size} bytes, got {len(raw_header)}"
                )
            parsed = json.loads(raw_header.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError(f".safetensors header is not a JSON object in {file_path}")
            return parsed

    def _resolve_with_cache(
        self, model_id: str, explicit_license: str | None = None
    ) -> tuple[str, str, str]:
        lowered = model_id.strip().lower()
        if not explicit_license and lowered in self.custom_license_cache:
            explicit_license = self.custom_license_cache[lowered]
        return resolve_model_license(model_id, explicit_license)

    def _parse_safetensors_file(
        self, file_path: Path, source_rel: str
    ) -> DiscoveredComponent | None:
        try:
            header = self.read_safetensors_header(file_path)
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None

        meta = header.get("__metadata__", {})
        if not isinstance(meta, dict):
            meta = {}

        model_id = (
            meta.get("model_id")
            or meta.get("name")
            or meta.get("_name_or_path")
            or meta.get("repo_id")
            or meta.get("base_model")
            or file_path.stem
        )
        explicit_lic = (
            meta.get("license")
            or meta.get("license_name")
            or meta.get("spdx_id")
            or header.get("license")
        )
        version = str(meta.get("version") or meta.get("revision") or "main")
        raw_lic, norm_lic, holder = self._resolve_with_cache(
            str(model_id), str(explicit_lic) if explicit_lic else None
        )
        if meta.get("author") or meta.get("copyright"):
            holder = str(meta.get("author") or meta.get("copyright"))

        return DiscoveredComponent(
            name=str(model_id),
            version=version,
            component_type=ComponentType.ML_MODEL,
            raw_license=raw_lic,
            normalized_license=norm_lic,
            source_file=source_rel,
            copyright_holder=holder,
            homepage=(
                f"https://huggingface.co/{model_id}"
                if "/" in str(model_id)
                else None
            ),
            metadata={
                "artifact_type": "safetensors_weights",
                "metadata": meta,
            },
        )

    def _parse_manifest_json(
        self, file_path: Path, source_rel: str
    ) -> list[DiscoveredComponent]:
        components: list[DiscoveredComponent] = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return components

        if not isinstance(data, dict):
            return components

        # Support multi-model array in model_config.json / model_manifest.json if present
        models_list = data.get("models")
        if isinstance(models_list, list):
            for entry in models_list:
                if isinstance(entry, dict):
                    comp = self._extract_component_from_manifest_dict(entry, file_path.name, source_rel)
                    if comp is not None:
                        components.append(comp)

        single_comp = self._extract_component_from_manifest_dict(data, file_path.name, source_rel)
        if single_comp is not None:
            components.append(single_comp)

        return components

    def _extract_component_from_manifest_dict(
        self, data: dict[str, Any], filename: str, source_rel: str
    ) -> DiscoveredComponent | None:
        model_id = (
            data.get("_name_or_path")
            or data.get("model_id")
            or data.get("repo_id")
            or data.get("base_model_name_or_path")
            or data.get("model_name")
            or data.get("pretrained_model_name_or_path")
        )
        if not model_id or not isinstance(model_id, str):
            return None

        explicit_lic = (
            data.get("license")
            or data.get("license_name")
            or data.get("model_license")
            or data.get("spdx_id")
        )
        # Do not conflate library version (transformers_version / _diffusers_version) with model revision
        version = str(
            data.get("version")
            or data.get("model_version")
            or data.get("revision")
            or data.get("_commit_hash")
            or "main"
        )
        raw_lic, norm_lic, holder = self._resolve_with_cache(
            model_id, str(explicit_lic) if explicit_lic else None
        )
        if data.get("author") or data.get("organization"):
            holder = str(data.get("author") or data.get("organization"))

        meta_dict: dict[str, Any] = {
            "artifact_type": "model_manifest",
            "manifest_file": filename,
            "model_type": data.get("model_type") or data.get("_class_name"),
        }
        if data.get("transformers_version"):
            meta_dict["transformers_version"] = data.get("transformers_version")
        if data.get("_diffusers_version"):
            meta_dict["diffusers_version"] = data.get("_diffusers_version")

        return DiscoveredComponent(
            name=model_id,
            version=version,
            component_type=ComponentType.ML_MODEL,
            raw_license=raw_lic,
            normalized_license=norm_lic,
            source_file=source_rel,
            copyright_holder=holder,
            homepage=f"https://huggingface.co/{model_id}" if "/" in model_id else None,
            metadata=meta_dict,
        )

    def _parse_code_or_env_file(
        self, file_path: Path, source_rel: str
    ) -> list[DiscoveredComponent]:
        components: list[DiscoveredComponent] = []
        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return components

        discovered_ids: list[tuple[str, str]] = []
        if file_path.suffix.lower() == ".py":
            try:
                tree = ast.parse(content, filename=source_rel)
                visitor = _ModelCallVisitor()
                visitor.visit(tree)
                discovered_ids.extend(visitor.discovered)
            except SyntaxError:
                # Fallback to line-by-line regex ignoring comment lines if syntax is invalid
                non_comment_lines = [
                    line.split("#", 1)[0]
                    for line in content.splitlines()
                    if not line.lstrip().startswith("#")
                ]
                stripped_content = "\n".join(non_comment_lines)
                for regex, method in (
                    (_FROM_PRETRAINED_RE, "from_pretrained"),
                    (_PIPELINE_MODEL_RE, "transformers_pipeline"),
                    (_HF_HUB_DOWNLOAD_RE, "hf_hub_download"),
                    (_SENTENCE_TRANSFORMER_RE, "sentence_transformer"),
                ):
                    for match in regex.finditer(stripped_content):
                        repo_id = match.group(1).strip()
                        if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                            discovered_ids.append((repo_id, method))
        else:
            for match in _ENV_MODEL_RE.finditer(content):
                repo_id = match.group(1).strip()
                if repo_id and not repo_id.startswith(".") and not repo_id.startswith("/"):
                    discovered_ids.append((repo_id, "env_declaration"))

        seen: set[str] = set()
        for repo_id, method in discovered_ids:
            if repo_id in seen:
                continue
            seen.add(repo_id)
            raw_lic, norm_lic, holder = self._resolve_with_cache(repo_id)
            components.append(
                DiscoveredComponent(
                    name=repo_id,
                    version="main",
                    component_type=ComponentType.ML_MODEL,
                    raw_license=raw_lic,
                    normalized_license=norm_lic,
                    source_file=source_rel,
                    copyright_holder=holder,
                    homepage=f"https://huggingface.co/{repo_id}" if "/" in repo_id else None,
                    metadata={
                        "artifact_type": "code_reference",
                        "detection_method": method,
                    },
                )
            )
        return components
