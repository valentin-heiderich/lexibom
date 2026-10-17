"""Machine-readable JSON SBOM and legal compliance report exporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lexibom import __version__
from lexibom.legal.evaluator import EvaluationResult, RiskLevel


class JsonComplianceReporter:
    """Exports structured SBOM and legal compliance audit results to JSON."""

    @staticmethod
    def build_payload(
        result: EvaluationResult, project_path: str = "."
    ) -> dict[str, Any]:
        """Build the JSON-serializable compliance report payload."""
        crit_components = sum(
            1 for f in result.findings if f.risk_level == RiskLevel.RISK_CRITICAL
        )
        warn_components = sum(
            1 for f in result.findings if f.risk_level == RiskLevel.RISK_WARNING
        )
        return {
            "tool": {
                "name": "LexiBOM",
                "version": __version__,
                "schema_version": "1.0.0",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_context": {
                "project_path": project_path,
                "target_distribution_type": result.target_distribution_type,
                "is_commercial": result.is_commercial,
            },
            "status": result.status.value,
            "summary": {
                "total_components": len(result.components),
                "critical_violations": result.critical_count,
                "warnings": result.warning_count,
                "critical_components": crit_components,
                "warning_components": warn_components,
                "compliant_components": result.compliant_count,
                "inter_license_conflicts": len(result.inter_license_conflicts),
                "by_component_type": {
                    "python": sum(
                        1 for c in result.components if c.component_type.value == "python"
                    ),
                    "node": sum(
                        1 for c in result.components if c.component_type.value == "node"
                    ),
                    "ml_model": sum(
                        1 for c in result.components if c.component_type.value == "ml_model"
                    ),
                },
            },
            "components": [c.to_dict() for c in result.components],
            "violations": [v.to_dict() for v in result.violations],
            "inter_license_conflicts": [c.to_dict() for c in result.inter_license_conflicts],
            "findings": [f.to_dict() for f in result.findings],
        }

    @classmethod
    def write_report(
        cls,
        result: EvaluationResult,
        output_path: Path,
        project_path: str = ".",
    ) -> Path:
        """Write compliance-report.json to disk and return the resolved path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = cls.build_payload(result, project_path=project_path)
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return output_path.resolve()
