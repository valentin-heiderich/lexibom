# LexiBOM

**LexiBOM** is an open-source and AI model weight license compliance scanner inspired by FOSSA, engineered specifically for **legal compliance, license compatibility conflict detection, and machine learning model weight licensing**.

Traditional Software Composition Analysis (SCA) tools focus on standard code dependencies (`npm`, `PyPI`) and CVEs. LexiBOM bridges the gap between traditional open-source code licenses (`MIT`, `Apache-2.0`, `GPL`, `AGPL`) and modern AI/ML licenses (`OpenRAIL-M`, `CC-BY-NC-4.0`, `Llama-3-Community`, `Gemma-Terms-of-Use`, and custom model riders).

---

## Key Capabilities

1. **Dual Scanner (Code + AI/ML Artifacts)**:
   - **Python Dependencies**: `requirements.txt`, `pyproject.toml` (PEP 621 & Poetry), `Pipfile.lock`.
   - **Node.js Dependencies**: `package.json`, `package-lock.json` (v1, v2, v3).
   - **AI/ML Model Artifacts**:
     - Hugging Face & Diffusers manifests (`config.json`, `model_index.json`, `model_config.json`, `adapter_config.json`).
     - Direct `.safetensors` binary header parser (reads the 8-byte little-endian size prefix and JSON `__metadata__` header without loading tensor weights into RAM).
     - Source code & `.env` scanner (`AutoModel*.from_pretrained(...)`, `DiffusionPipeline.from_pretrained(...)`, `pipeline(...)`, `snapshot_download(...)`, `HF_MODEL_ID`).
2. **License Normalization Engine (`lexibom.legal.taxonomy`)**:
   - Normalizes raw license strings into canonical SPDX identifiers or ML taxonomy IDs (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `MPL-2.0`, `LGPL-3.0-only`, `GPL-2.0-only`, `GPL-3.0-only`, `AGPL-3.0-only`, `AGPL-3.0-or-later`, `OpenRAIL-M`, `Llama-3-Community`, `CC-BY-NC-4.0`, etc.).
3. **Legal Compatibility & Risk Matrix (`lexibom.legal.evaluator`)**:
   - Evaluates discovered components against target deployment modes (`SAAS_HOSTED`, `PROPRIETARY_DISTRIBUTED`, `OPEN_SOURCE`) and commercial context (`commercial` vs `non-commercial`).
   - Detects:
     - **Copyleft Contamination (`RISK_CRITICAL`)**: e.g., `AGPL-3.0` in `SAAS_HOSTED` or `PROPRIETARY_DISTRIBUTED`; `GPL-2.0`/`GPL-3.0` in `PROPRIETARY_DISTRIBUTED`.
     - **Non-Commercial AI/Data Restrictions (`RISK_CRITICAL`)**: e.g., `CC-BY-NC-4.0` or research-only weights in commercial deployments.
     - **Behavioral / Responsible AI Restrictions (`RISK_WARNING`)**: e.g., `OpenRAIL-M` Attachment A acceptable use restrictions (biometrics, medical diagnosis, law enforcement) and mandatory downstream pass-through clauses.
     - **Community Model Riders (`RISK_WARNING`)**: e.g., `Llama-3-Community` 700M Monthly Active Users commercial threshold and mandatory attribution.
     - **Patent Clause Friction (`RISK_WARNING`)**: Flags `Apache-2.0` (Section 3 patent termination) vs. `GPL-2.0-only` incompatibility.
4. **Structured Output Formats**:
   - Rich CLI summary & violation tables (`lexibom.reporters.terminal`).
   - Machine-readable SBOM & compliance report (`compliance-report.json`).
   - Legal attribution notice file (`THIRD_PARTY_NOTICES.md`) containing full license texts for compliant dependencies.

---

## Quick Start & Usage

### Run a Compliance Scan via Poetry

```bash
poetry run lexibom scan ./tests/fixtures/sample_ai_app --context commercial-saas
```

### Supported Deployment Contexts (`--context`)

- `commercial-saas` -> `SAAS_HOSTED` (`is_commercial=True`)
- `proprietary-distributed` / `commercial-distributed` -> `PROPRIETARY_DISTRIBUTED` (`is_commercial=True`)
- `open-source` -> `OPEN_SOURCE` (`is_commercial=True`)
- `research-noncommercial` -> `SAAS_HOSTED` (`is_commercial=False`)

### Additional Commands

```bash
# Normalize and inspect a raw license string
poetry run lexibom normalize "CreativeML OpenRAIL-M"

# View the full canonical license taxonomy table
poetry run lexibom taxonomy

# Run unit tests and type checking
poetry run pytest
poetry run mypy lexibom tests
```
