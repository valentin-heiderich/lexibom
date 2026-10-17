# Prompt: Build "LexiBOM" — An Open-Source & AI Model Weight License Compliance Scanner (MVP)

You are tasked with building the MVP for **LexiBOM**, a CLI and lightweight engine inspired by FOSSA, focused squarely on **legal compliance, license compatibility conflict detection, and machine learning model weight licensing**.

Traditional SCA tools focus primarily on standard code dependencies (npm, PyPI) and CVEs. LexiBOM must bridge the gap between traditional code licenses (MIT, Apache 2.0, GPL, AGPL) and modern AI/ML licenses (OpenRAIL, CC-BY-NC, Llama Community License, Custom Model Riders).

---

## 1. Core Objectives & Scope

Build an MVP CLI tool (written in Python with `click` or `typer`) that inspects a target project directory, identifies both code libraries and ML model artifacts, maps their licenses, runs a legal compatibility audit, and generates a structured compliance report.

### Key Capabilities:
1. **Dual Scanner**:
   - **Code Dependencies**: Parse Python (`requirements.txt`, `pyproject.toml`, `Pipfile.lock`) and Node (`package.json`, `package-lock.json`).
   - **AI/ML Artifacts**: Identify local weights and model manifests (`config.json`, `model_index.json`, Hugging Face model IDs in code/configs, `.safetensors` header metadata).
2. **License Normalization Engine**:
   - Normalize license strings into canonical SPDX identifiers or custom ML taxonomy IDs (e.g., `MIT`, `Apache-2.0`, `GPL-3.0-only`, `AGPL-3.0-or-later`, `OpenRAIL-M`, `Llama-3-Community`, `CC-BY-NC-4.0`).
3. **Legal Compatibility & Risk Matrix**:
   - Evaluate licenses against project deployment mode: `PROPRIETARY_DISTRIBUTED` (binaries/on-prem), `SAAS_HOSTED` (network access), or `OPEN_SOURCE`.
   - Identify critical flags:
     - **Copyleft Contamination**: e.g., GPL-3.0 in proprietary distributed builds; AGPL-3.0 in SaaS builds.
     - **Non-Commercial Restrictions (AI/Data)**: e.g., `CC-BY-NC-4.0` or research-only weights used in a commercial product.
     - **Behavioral / Use-Case Restrictions (RAIL)**: Surface mandatory downstream use restrictions (e.g., OpenRAIL acceptable use policies on biometric identification or medical diagnosis).
     - **Patent Clauses**: Flag Apache 2.0 vs. GPLv2 friction.
4. **Output Formats**:
   - Clean CLI summary table (via `rich`).
   - Exportable legal compliance report (`compliance-report.json` and `THIRD_PARTY_NOTICES.md`).

---

## 2. Architecture & File Layout

Structure the project cleanly:

```text
lexibom/
├── pyproject.toml
├── README.md
├── lexibom/
│   ├── __init__.py
│   ├── cli.py                     # Typer/Click CLI entry point
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base.py                # Abstract parser interface
│   │   ├── python_parser.py       # requirements.txt / pyproject.toml
│   │   ├── node_parser.py         # package.json
│   │   └── ml_model_parser.py     # safetensors metadata, huggingface configs
│   ├── legal/
│   │   ├── __init__.py
│   │   ├── taxonomy.py            # License classifications (Permissive, Copyleft, Rail, NC)
│   │   ├── rules_matrix.json      # Incompatibility rules & risk triggers
│   │   └── evaluator.py           # Compatibility & compliance engine
│   └── reporters/
│       ├── __init__.py
│       ├── terminal.py            # Rich terminal tables
│       ├── markdown.py            # Attribution & notice file generator
│       └── json_export.py         # Machine-readable SBOM output
└── tests/
    ├── test_evaluator.py
    ├── test_ml_parser.py
    └── fixtures/                  # Mock package files and model config files
```

---

## 3. Detailed Component Specifications

### A. The ML & Neural Network Weights Parser (`parsers/ml_model_parser.py`)
- Detect model references:
  1. **Config manifests**: Look for `config.json` containing `_name_or_path` (Hugging Face repo IDs).
  2. **Direct Safetensors headers**: Read the JSON header at the beginning of `.safetensors` files without loading tensors into RAM to extract embedded license metadata.
  3. **Declared models in code/env**: Simple regex scanner for `AutoModel.from_pretrained("<repo>")` patterns.
- Query/resolve license info:
  - Cache known model licenses locally (e.g., `meta-llama/Llama-3-8B` -> `Llama-3-Community`, `stabilityai/stable-diffusion-xl-base-1.0` -> `CreativeML OpenRAIL-M`, `mistralai/Mistral-7B-v0.1` -> `Apache-2.0`).

### B. Legal Rules Matrix (`legal/rules_matrix.json`)
Define an extensible JSON matrix with clear risk tiers:
- **`RISK_CRITICAL`**: 
  - `AGPL-3.0` in a `SAAS_HOSTED` or `PROPRIETARY_DISTRIBUTED` project.
  - `GPL-2.0` / `GPL-3.0` in a `PROPRIETARY_DISTRIBUTED` project.
  - `CC-BY-NC-*` or `NonCommercial` model weight license in a `COMMERCIAL` target context.
- **`RISK_WARNING`**:
  - `OpenRAIL` or `Llama-Community`: Highlight required operational terms (e.g., Llama threshold of 700M monthly active users requiring a commercial license; OpenRAIL downstream ethical usage pass-through clauses).
  - Weak copyleft (`LGPL`, `MPL-2.0`) requiring dynamic linking documentation.
- **`RISK_COMPLIANT`**:
  - `MIT`, `Apache-2.0`, `BSD-3-Clause` when attribution is satisfied.

### C. The Evaluator (`legal/evaluator.py`)
Input: `List[DiscoveredComponent]`, `target_distribution_type: str`, `is_commercial: bool`.
Output:
- Compatibility status (`PASS`, `FLAGGED`, `FAIL`).
- List of violations with legal explanations (e.g., *"Model weight 'meta-llama/Llama-3' imposes user-count and usage restrictions that require review against terms of service."*).
- Actionable remediation advice (e.g., *"Replace component X with Apache-2.0 alternative Y"*).

---

## 4. Acceptance Criteria & Demo Scenario

1. The project must run via `poetry run lexibom scan ./path/to/project --context commercial-saas`.
2. Include a realistic test fixture in `tests/fixtures/sample_ai_app/` that includes:
   - A `package.json` with permissive libraries (e.g., `axios`).
   - A `requirements.txt` containing an AGPL dependency (e.g., an AGPL scraper).
   - A mock `model_config.json` referencing a model under an OpenRAIL or CC-BY-NC license.
3. Running the scan on the fixture must:
   - Accurately flag the AGPL dependency as critical for SaaS context.
   - Accurately flag the CC-BY-NC or OpenRAIL model weights with specific risk notes.
   - Generate a valid `THIRD_PARTY_NOTICES.md` containing full attribution texts for compliant libraries.
4. Keep the code strictly modular, fully typed with Python type hints, and include comprehensive unit tests.