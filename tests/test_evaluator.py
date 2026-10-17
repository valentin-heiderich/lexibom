"""Unit and integration tests for LexiBOM license taxonomy, legal evaluator, and CLI pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lexibom.cli import ProjectScanner, app, run_scan_pipeline
from lexibom.legal.evaluator import (
    ComplianceEvaluator,
    ComplianceStatus,
    DeploymentMode,
    RiskLevel,
)
from lexibom.legal.taxonomy import (
    LicenseCategory,
    classify_license,
    normalize_license,
)
from lexibom.parsers.base import ComponentType, DiscoveredComponent
from lexibom.parsers.node_parser import NodeDependencyParser, resolve_node_package_license
from lexibom.parsers.python_parser import (
    PythonDependencyParser,
    resolve_python_package_license,
)


def _make_component(
    name: str,
    raw_license: str,
    comp_type: ComponentType = ComponentType.PYTHON_PACKAGE,
    version: str = "1.0.0",
) -> DiscoveredComponent:
    return DiscoveredComponent(
        name=name,
        version=version,
        component_type=comp_type,
        raw_license=raw_license,
        normalized_license=normalize_license(raw_license),
        source_file="mock_manifest",
    )


def test_license_normalization_and_compound_spdx_expressions() -> None:
    """Verify canonical SPDX/ML normalization and compound OR/AND/WITH SPDX expression evaluation."""
    assert normalize_license("MIT License") == "MIT"
    assert normalize_license("Apache 2.0") == "Apache-2.0"
    assert normalize_license("GPLv3") == "GPL-3.0-only"
    assert normalize_license("GPL-3.0+") == "GPL-3.0-or-later"
    assert normalize_license("AGPLv3") == "AGPL-3.0-only"
    assert normalize_license("AGPL-3.0-or-later") == "AGPL-3.0-or-later"
    assert normalize_license("CreativeML OpenRAIL-M") == "OpenRAIL-M"
    assert normalize_license("Llama 3 Community License") == "Llama-3-Community"
    assert normalize_license("CC BY-NC 4.0") == "CC-BY-NC-4.0"
    assert normalize_license("research-only") == "NonCommercial-Research-Only"
    assert normalize_license("") == "UNKNOWN"

    # Compound SPDX expressions (OR elects least restrictive; AND requires most restrictive)
    assert normalize_license("MIT OR GPL-3.0-only") == "MIT"
    assert normalize_license("(MIT OR Apache-2.0)") == "MIT"
    assert normalize_license("Apache-2.0 AND BSD-3-Clause") == "Apache-2.0"
    assert normalize_license("MIT AND GPL-3.0-only") == "GPL-3.0-only"
    assert normalize_license("GPL-3.0-only AND (MIT OR Apache-2.0)") == "GPL-3.0-only"
    assert normalize_license("Apache-2.0 WITH LLVM-exception") == "Apache-2.0"

    assert classify_license("MIT").category == LicenseCategory.PERMISSIVE
    assert classify_license("AGPL-3.0-only").category == LicenseCategory.NETWORK_COPYLEFT
    assert classify_license("OpenRAIL-M").category == LicenseCategory.BEHAVIORAL_RAIL
    assert classify_license("Llama-3-Community").category == LicenseCategory.COMMUNITY_RESTRICTED
    assert classify_license("CC-BY-NC-4.0").category == LicenseCategory.NON_COMMERCIAL


def test_package_name_heuristics_do_not_false_positive_on_mpl_substrings() -> None:
    """Ensure packages containing 'mpl' as a substring (e.g. template-engine, sampler) are not misclassified as MPL-2.0."""
    _, norm_tmpl, _ = resolve_python_package_license("jinja-template-helper")
    assert norm_tmpl == "UNKNOWN"

    _, norm_sampler, _ = resolve_python_package_license("audio-sampler-pro")
    assert norm_sampler == "UNKNOWN"

    _, norm_simple, _ = resolve_python_package_license("simplejson")
    assert norm_simple == "MIT"

    _, norm_node_tmpl, _ = resolve_node_package_license("html-template-loader")
    assert norm_node_tmpl == "UNKNOWN"

    # Explicit token-boundary synthetic fixture names still work as expected
    _, norm_mock_mpl, _ = resolve_python_package_license("mock-mpl-plugin")
    assert norm_mock_mpl == "MPL-2.0"

    # Inline hint preserves known copyright holder
    _, norm_agpl, holder_agpl = resolve_python_package_license(
        "agpl-scraper", inline_hint="AGPL-3.0-only"
    )
    assert norm_agpl == "AGPL-3.0-only"
    assert holder_agpl == "Open Scraper Collective"


def test_evaluator_agpl_critical_in_saas_and_distributed() -> None:
    """AGPL-3.0 must trigger RISK_CRITICAL and FAIL in SAAS_HOSTED and PROPRIETARY_DISTRIBUTED."""
    evaluator = ComplianceEvaluator()
    comps = [
        _make_component("axios", "MIT", ComponentType.NODE_PACKAGE),
        _make_component("agpl-scraper", "AGPL-3.0-only", ComponentType.PYTHON_PACKAGE),
    ]

    res_saas = evaluator.evaluate(
        comps, target_distribution_type=DeploymentMode.SAAS_HOSTED.value, is_commercial=True
    )
    assert res_saas.status == ComplianceStatus.FAIL
    assert res_saas.critical_count == 1
    crit = res_saas.violations[0]
    assert crit.component.name == "agpl-scraper"
    assert crit.risk_level == RiskLevel.RISK_CRITICAL
    assert crit.flag_type == "COPYLEFT_CONTAMINATION"
    assert "Corresponding Source" in crit.legal_explanation

    res_dist = evaluator.evaluate(
        comps,
        target_distribution_type=DeploymentMode.PROPRIETARY_DISTRIBUTED.value,
        is_commercial=True,
    )
    assert res_dist.status == ComplianceStatus.FAIL
    assert res_dist.critical_count == 1


def test_evaluator_gpl_proprietary_distributed_vs_saas() -> None:
    """GPL-3.0 must be RISK_CRITICAL in PROPRIETARY_DISTRIBUTED and RISK_WARNING in SAAS_HOSTED."""
    evaluator = ComplianceEvaluator()
    comps = [_make_component("pyqt6", "GPL-3.0-only")]

    res_dist = evaluator.evaluate(
        comps,
        target_distribution_type=DeploymentMode.PROPRIETARY_DISTRIBUTED.value,
        is_commercial=True,
    )
    assert res_dist.status == ComplianceStatus.FAIL
    assert res_dist.violations[0].risk_level == RiskLevel.RISK_CRITICAL
    assert res_dist.violations[0].flag_type == "COPYLEFT_CONTAMINATION"

    res_saas = evaluator.evaluate(
        comps,
        target_distribution_type=DeploymentMode.SAAS_HOSTED.value,
        is_commercial=True,
    )
    assert res_saas.status == ComplianceStatus.FLAGGED
    assert res_saas.violations[0].risk_level == RiskLevel.RISK_WARNING


def test_evaluator_noncommercial_model_weights() -> None:
    """CC-BY-NC-4.0 weights must be RISK_CRITICAL in commercial contexts and RISK_COMPLIANT in non-commercial research."""
    evaluator = ComplianceEvaluator()
    comps = [
        _make_component(
            "lmsys/vicuna-13b-v1.5", "CC-BY-NC-4.0", ComponentType.ML_MODEL
        )
    ]

    res_comm = evaluator.evaluate(
        comps, target_distribution_type=DeploymentMode.SAAS_HOSTED.value, is_commercial=True
    )
    assert res_comm.status == ComplianceStatus.FAIL
    assert res_comm.violations[0].risk_level == RiskLevel.RISK_CRITICAL
    assert res_comm.violations[0].flag_type == "NON_COMMERCIAL_RESTRICTION"

    res_research = evaluator.evaluate(
        comps, target_distribution_type=DeploymentMode.SAAS_HOSTED.value, is_commercial=False
    )
    assert res_research.status == ComplianceStatus.PASS
    assert res_research.critical_count == 0


def test_evaluator_openrail_and_llama_warnings() -> None:
    """OpenRAIL-M and Llama-3-Community must surface RISK_WARNING with specific operational and behavioral notes."""
    evaluator = ComplianceEvaluator()
    comps = [
        _make_component(
            "stabilityai/stable-diffusion-xl-base-1.0",
            "CreativeML OpenRAIL-M",
            ComponentType.ML_MODEL,
        ),
        _make_component(
            "meta-llama/Llama-3-8B",
            "Llama-3-Community",
            ComponentType.ML_MODEL,
        ),
    ]

    res = evaluator.evaluate(
        comps, target_distribution_type=DeploymentMode.SAAS_HOSTED.value, is_commercial=True
    )
    assert res.status == ComplianceStatus.FLAGGED
    assert res.critical_count == 0
    assert res.warning_count == 2

    by_name = {v.component.name: v for v in res.violations}
    rail_v = by_name["stabilityai/stable-diffusion-xl-base-1.0"]
    assert rail_v.flag_type == "BEHAVIORAL_RAIL_RESTRICTION"
    assert "biometric" in rail_v.legal_explanation.lower()
    assert "medical diagnosis" in rail_v.legal_explanation.lower()

    llama_v = by_name["meta-llama/Llama-3-8B"]
    assert llama_v.flag_type == "MODEL_COMMUNITY_RIDER"
    assert "700 million" in llama_v.legal_explanation.lower() or "700m" in llama_v.legal_explanation.lower()


def test_evaluator_patent_clause_friction_apache2_vs_gplv2() -> None:
    """Detect Apache-2.0 vs GPL-2.0-only patent termination friction while keeping findings 1-to-1 with components."""
    evaluator = ComplianceEvaluator()
    comps = [
        _make_component("transformers", "Apache-2.0", ComponentType.PYTHON_PACKAGE),
        _make_component("mysqlclient", "GPL-2.0-only", ComponentType.PYTHON_PACKAGE),
    ]

    res = evaluator.evaluate(
        comps, target_distribution_type=DeploymentMode.OPEN_SOURCE.value, is_commercial=True
    )
    assert len(res.findings) == len(comps)
    assert len(res.inter_license_conflicts) == 1
    assert any(v.flag_type == "PATENT_CLAUSE_FRICTION" for v in res.violations)
    conflict = res.inter_license_conflicts[0]
    assert "Apache License 2.0 Section 3" in conflict.legal_explanation


def test_python_and_node_lockfile_parsers_and_cross_manifest_deduplication(
    tmp_path: Path,
) -> None:
    """Verify pyproject.toml groups, compound specifiers, lockfiles, and ProjectScanner cross-manifest deduplication."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo"
dependencies = ["requests>=2.31.0,<3.0.0", "chardet==5.2.0"]

[tool.poetry.dependencies]
python = "^3.11"
rich = "^13.7.0"

[tool.poetry.group.dev.dependencies]
mypy = ">=1.5.0"
""",
        encoding="utf-8",
    )
    pipfile_lock = tmp_path / "Pipfile.lock"
    pipfile_lock.write_text(
        json.dumps(
            {
                "default": {"fastapi": {"version": "==0.110.0"}, "requests": {"version": "==2.32.1"}},
                "develop": {"pytest": {"version": "==8.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({"dependencies": {"axios": "^1.6.0"}}),
        encoding="utf-8",
    )
    pkg_lock = tmp_path / "package-lock.json"
    pkg_lock.write_text(
        json.dumps(
            {
                "name": "web-client",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "web-client", "version": "1.0.0"},
                    "node_modules/axios": {"version": "1.6.8", "license": "MIT"},
                    "node_modules/dompurify": {"version": "3.0.9", "license": "MPL-2.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    scanner = ProjectScanner()
    merged = scanner.scan(tmp_path)
    by_name = {(c.component_type.value, c.name.lower()): c for c in merged}

    # requests was in both pyproject.toml (>=2.31.0,<3.0.0) and Pipfile.lock (==2.32.1) -> merged with lockfile version 2.32.1
    req_comp = by_name[("python", "requests")]
    assert req_comp.version == "2.32.1"
    assert req_comp.purl == "pkg:pypi/requests@2.32.1"
    assert len(req_comp.metadata["source_files"]) == 2

    # axios was in both package.json (^1.6.0) and package-lock.json (1.6.8) -> merged with lockfile version 1.6.8
    axios_comp = by_name[("node", "axios")]
    assert axios_comp.version == "1.6.8"
    assert len(axios_comp.metadata["source_files"]) == 2

    # Poetry group dev dependency mypy discovered
    assert ("python", "mypy") in by_name
    assert by_name[("python", "mypy")].normalized_license == "MIT"


def test_sample_ai_app_fixture_end_to_end_and_cli(tmp_path: Path) -> None:
    """Acceptance test: scan tests/fixtures/sample_ai_app/ under commercial-saas context."""
    fixture_dir = Path(__file__).parent / "fixtures" / "sample_ai_app"
    assert fixture_dir.is_dir()

    result = run_scan_pipeline(fixture_dir, context="commercial-saas")
    assert result.status == ComplianceStatus.FAIL
    assert result.target_distribution_type == "SAAS_HOSTED"
    assert result.is_commercial is True

    # 1. Verify AGPL dependency is flagged as RISK_CRITICAL
    agpl_violations = [
        v
        for v in result.violations
        if v.component.name == "agpl-scraper" and v.risk_level == RiskLevel.RISK_CRITICAL
    ]
    assert len(agpl_violations) == 1
    assert agpl_violations[0].flag_type == "COPYLEFT_CONTAMINATION"

    # 2. Verify CC-BY-NC-4.0 model is flagged as RISK_CRITICAL
    nc_violations = [
        v
        for v in result.violations
        if v.component.name == "lmsys/vicuna-13b-v1.5"
        and v.risk_level == RiskLevel.RISK_CRITICAL
    ]
    assert len(nc_violations) == 1
    assert nc_violations[0].flag_type == "NON_COMMERCIAL_RESTRICTION"

    # 3. Verify OpenRAIL-M and Llama-3-Community models are flagged with specific risk notes
    rail_violations = [
        v
        for v in result.violations
        if v.component.name == "stabilityai/stable-diffusion-xl-base-1.0"
        and v.risk_level == RiskLevel.RISK_WARNING
    ]
    assert len(rail_violations) == 1
    assert rail_violations[0].flag_type == "BEHAVIORAL_RAIL_RESTRICTION"

    llama_violations = [
        v
        for v in result.violations
        if v.component.name == "meta-llama/Llama-3-8B"
        and v.risk_level == RiskLevel.RISK_WARNING
    ]
    assert len(llama_violations) == 1
    assert llama_violations[0].flag_type == "MODEL_COMMUNITY_RIDER"

    # 4. Verify CLI execution and report generation
    runner = CliRunner()
    json_out = tmp_path / "compliance-report.json"
    notices_out = tmp_path / "THIRD_PARTY_NOTICES.md"
    cli_res = runner.invoke(
        app,
        [
            "scan",
            str(fixture_dir),
            "--context",
            "commercial-saas",
            "--json-out",
            str(json_out),
            "--notices-out",
            str(notices_out),
        ],
    )
    assert cli_res.exit_code == 0, cli_res.output
    assert json_out.is_file()
    assert notices_out.is_file()

    # Ensure fixture directory was not mutated with report files
    assert not (fixture_dir / "compliance-report.json").exists()
    assert not (fixture_dir / "THIRD_PARTY_NOTICES.md").exists()

    notices_text = notices_out.read_text(encoding="utf-8")
    assert "axios" in notices_text
    assert "Permission is hereby granted, free of charge" in notices_text
    assert "Apache License, Version 2.0" in notices_text
    assert "mistralai/Mistral-7B-v0.1" in notices_text

    json_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert json_payload["status"] == "FAIL"
    assert json_payload["summary"]["critical_violations"] == 2
    assert json_payload["summary"]["warnings"] == 2
    assert json_payload["summary"]["compliant_components"] == 9
