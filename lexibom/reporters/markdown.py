"""Generator for THIRD_PARTY_NOTICES.md attribution and license notices."""

from __future__ import annotations

from pathlib import Path

from lexibom.legal.evaluator import EvaluationResult, RiskLevel
from lexibom.legal.taxonomy import classify_license


class MarkdownNoticeReporter:
    """Generates a THIRD_PARTY_NOTICES.md file with full attribution texts for compliant libraries."""

    @staticmethod
    def generate_markdown(result: EvaluationResult) -> str:
        """Build the markdown string for THIRD_PARTY_NOTICES.md."""
        lines: list[str] = [
            "# THIRD-PARTY SOFTWARE & AI MODEL NOTICES",
            "",
            "This file contains attribution notices and full license texts for third-party open-source",
            "software libraries and machine learning model artifacts discovered by **LexiBOM**.",
            "",
            f"- **Target Deployment Mode**: `{result.target_distribution_type}`",
            f"- **Commercial Context**: `{'Commercial' if result.is_commercial else 'Non-Commercial'}`",
            f"- **Compliance Status**: `{result.status.value}`",
            "",
            "---",
            "",
            "## 1. Summary of Compliant & Attributed Components",
            "",
            "| Component | Version | Type | License | Source |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        compliant_findings = [
            f
            for f in result.findings
            if not f.rule_id.startswith("CONFLICT-")
            and f.risk_level == RiskLevel.RISK_COMPLIANT
        ]
        conditional_findings = [
            f
            for f in result.findings
            if not f.rule_id.startswith("CONFLICT-")
            and f.risk_level == RiskLevel.RISK_WARNING
            and f.component.normalized_license != "UNKNOWN"
        ]

        for f in compliant_findings:
            c = f.component
            lines.append(
                f"| `{c.name}` | `{c.version}` | `{c.component_type.value}` | `{c.normalized_license}` | `{c.source_file}` |"
            )

        if not compliant_findings:
            lines.append("| _None_ | - | - | - | - |")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 2. Full Attribution & License Notices (Compliant Libraries)",
                "",
            ]
        )

        for f in compliant_findings:
            c = f.component
            lic_info = f.license_info or classify_license(c.normalized_license)
            lines.extend(
                [
                    f"### {c.name} ({c.version})",
                    "",
                    f"- **Component Type**: `{c.component_type.value}`",
                    f"- **SPDX / Canonical License**: `{lic_info.canonical_id}` ({lic_info.name})",
                    f"- **Copyright**: Copyright (c) {c.copyright_holder}",
                ]
            )
            if c.homepage:
                lines.append(f"- **Homepage**: {c.homepage}")
            lines.extend(
                [
                    f"- **Discovered In**: `{c.source_file}`",
                    "",
                    "```text",
                    f"Copyright (c) {c.copyright_holder}",
                    "",
                    lic_info.notice_text.strip(),
                    "```",
                    "",
                ]
            )

        if conditional_findings:
            lines.extend(
                [
                    "---",
                    "",
                    "## 3. Conditional / Behavioral Model & Weak Copyleft Notices (Flagged for Review)",
                    "",
                ]
            )
            for f in conditional_findings:
                c = f.component
                lic_info = f.license_info or classify_license(c.normalized_license)
                lines.extend(
                    [
                        f"### {c.name} ({c.version}) — [{f.flag_type}]",
                        "",
                        f"- **License**: `{lic_info.canonical_id}` ({lic_info.name})",
                        f"- **Copyright**: Copyright (c) {c.copyright_holder}",
                        f"- **Legal Note**: {f.legal_explanation}",
                        "",
                        "```text",
                        f"Copyright (c) {c.copyright_holder}",
                        "",
                        lic_info.notice_text.strip(),
                        "```",
                        "",
                    ]
                )

        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def write_report(cls, result: EvaluationResult, output_path: Path) -> Path:
        """Write THIRD_PARTY_NOTICES.md to disk and return the resolved path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate_markdown(result)
        output_path.write_text(content, encoding="utf-8")
        return output_path.resolve()
