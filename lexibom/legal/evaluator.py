"""Legal compatibility and license compliance evaluation engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from lexibom.legal.taxonomy import (
    LicenseCategory,
    LicenseInfo,
    classify_license,
    normalize_license,
)
from lexibom.parsers.base import DiscoveredComponent


class RiskLevel(str, Enum):
    """Risk classification tiers defined by the LexiBOM legal rules matrix."""

    RISK_CRITICAL = "RISK_CRITICAL"
    RISK_WARNING = "RISK_WARNING"
    RISK_COMPLIANT = "RISK_COMPLIANT"


class ComplianceStatus(str, Enum):
    """Overall project compliance audit status."""

    PASS = "PASS"
    FLAGGED = "FLAGGED"
    FAIL = "FAIL"


class DeploymentMode(str, Enum):
    """Supported software and AI deployment distribution modes."""

    PROPRIETARY_DISTRIBUTED = "PROPRIETARY_DISTRIBUTED"
    SAAS_HOSTED = "SAAS_HOSTED"
    OPEN_SOURCE = "OPEN_SOURCE"


@dataclass
class LicenseViolation:
    """Represents a legal risk, violation, or compliance finding for a component."""

    component: DiscoveredComponent
    rule_id: str
    risk_level: RiskLevel
    flag_type: str
    legal_explanation: str
    remediation_advice: str
    obligations: list[str] = field(default_factory=list)
    license_info: LicenseInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding/violation into a dictionary."""
        return {
            "component_name": self.component.name,
            "component_version": self.component.version,
            "component_type": self.component.component_type.value,
            "source_file": self.component.source_file,
            "raw_license": self.component.raw_license,
            "normalized_license": self.component.normalized_license,
            "license_category": (
                self.license_info.category.value if self.license_info else LicenseCategory.UNKNOWN.value
            ),
            "rule_id": self.rule_id,
            "risk_level": self.risk_level.value,
            "flag_type": self.flag_type,
            "legal_explanation": self.legal_explanation,
            "remediation_advice": self.remediation_advice,
            "obligations": self.obligations,
        }


@dataclass
class EvaluationResult:
    """Complete result of running the LexiBOM legal compliance evaluator."""

    status: ComplianceStatus
    target_distribution_type: str
    is_commercial: bool
    components: list[DiscoveredComponent]
    findings: list[LicenseViolation]
    violations: list[LicenseViolation]
    inter_license_conflicts: list[LicenseViolation] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Number of RISK_CRITICAL violations."""
        return sum(1 for v in self.violations if v.risk_level == RiskLevel.RISK_CRITICAL)

    @property
    def warning_count(self) -> int:
        """Number of RISK_WARNING violations."""
        return sum(1 for v in self.violations if v.risk_level == RiskLevel.RISK_WARNING)

    @property
    def compliant_count(self) -> int:
        """Number of RISK_COMPLIANT components."""
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.RISK_COMPLIANT)

    @property
    def compliant_components(self) -> list[DiscoveredComponent]:
        """Return all components that are RISK_COMPLIANT (or require attribution notices)."""
        return [
            f.component
            for f in self.findings
            if f.risk_level == RiskLevel.RISK_COMPLIANT
        ]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the evaluation result to a dictionary."""
        return {
            "status": self.status.value,
            "target_distribution_type": self.target_distribution_type,
            "is_commercial": self.is_commercial,
            "summary": {
                "total_components": len(self.components),
                "critical_violations": self.critical_count,
                "warnings": self.warning_count,
                "compliant": self.compliant_count,
                "inter_license_conflicts": len(self.inter_license_conflicts),
            },
            "violations": [v.to_dict() for v in self.violations],
            "inter_license_conflicts": [c.to_dict() for c in self.inter_license_conflicts],
            "findings": [f.to_dict() for f in self.findings],
        }


DEFAULT_RULES_MATRIX_PATH = Path(__file__).with_name("rules_matrix.json")


class ComplianceEvaluator:
    """Evaluates discovered software and ML model components against legal rules."""

    def __init__(self, rules_matrix_path: Path | None = None) -> None:
        self.rules_matrix_path = rules_matrix_path or DEFAULT_RULES_MATRIX_PATH
        with self.rules_matrix_path.open("r", encoding="utf-8") as fh:
            self.matrix: dict[str, Any] = json.load(fh)
        self.rules: list[dict[str, Any]] = self.matrix.get("rules", [])
        self.context_presets: dict[str, dict[str, Any]] = self.matrix.get("context_presets", {})
        self.recommended_alternatives: dict[str, str] = self.matrix.get(
            "recommended_alternatives", {}
        )
        self.inter_license_rules: list[dict[str, Any]] = self.matrix.get(
            "inter_license_conflicts", []
        )

    def resolve_context(
        self, context_or_distribution: str, is_commercial: bool | None = None
    ) -> tuple[str, bool]:
        """Resolve a CLI context preset or raw distribution mode into (distribution_type, is_commercial)."""
        cleaned = context_or_distribution.strip()
        lowered = cleaned.lower()

        if lowered in self.context_presets:
            preset = self.context_presets[lowered]
            dist = str(preset["target_distribution_type"])
            comm = bool(preset["is_commercial"]) if is_commercial is None else is_commercial
            return dist, comm

        upper = cleaned.upper().replace("-", "_")
        if upper in (
            DeploymentMode.PROPRIETARY_DISTRIBUTED.value,
            DeploymentMode.SAAS_HOSTED.value,
            DeploymentMode.OPEN_SOURCE.value,
        ):
            return upper, (True if is_commercial is None else is_commercial)

        # Heuristic resolution for flexible context strings
        comm_inferred = is_commercial if is_commercial is not None else ("noncommercial" not in lowered and "non-commercial" not in lowered and "research" not in lowered)
        if "saas" in lowered or "hosted" in lowered or "cloud" in lowered:
            return DeploymentMode.SAAS_HOSTED.value, comm_inferred
        if "open" in lowered or "oss" in lowered:
            return DeploymentMode.OPEN_SOURCE.value, comm_inferred
        if "prop" in lowered or "dist" in lowered or "onprem" in lowered or "on-prem" in lowered or "binary" in lowered:
            return DeploymentMode.PROPRIETARY_DISTRIBUTED.value, comm_inferred

        raise ValueError(
            f"Unsupported deployment context '{context_or_distribution}'. "
            f"Expected one of {list(self.context_presets.keys())} or "
            f"{[m.value for m in DeploymentMode]}."
        )

    def evaluate(
        self,
        components: list[DiscoveredComponent],
        target_distribution_type: str = DeploymentMode.SAAS_HOSTED.value,
        is_commercial: bool = True,
    ) -> EvaluationResult:
        """Evaluate a list of components against the target distribution type and commercial flag."""
        dist_type, comm_flag = self.resolve_context(target_distribution_type, is_commercial)

        findings: list[LicenseViolation] = []
        violations: list[LicenseViolation] = []

        for comp in components:
            canonical = normalize_license(comp.normalized_license or comp.raw_license)
            comp.normalized_license = canonical
            lic_info = classify_license(canonical)

            finding = self._evaluate_single_component(
                comp=comp,
                lic_info=lic_info,
                dist_type=dist_type,
                is_commercial=comm_flag,
            )
            findings.append(finding)
            if finding.risk_level in (RiskLevel.RISK_CRITICAL, RiskLevel.RISK_WARNING):
                violations.append(finding)

        # Evaluate inter-license conflicts (e.g., Apache-2.0 vs GPL-2.0-only patent clause friction)
        inter_conflicts = self._evaluate_inter_license_conflicts(components)
        for conflict in inter_conflicts:
            violations.append(conflict)

        # Determine overall status
        if any(v.risk_level == RiskLevel.RISK_CRITICAL for v in violations):
            status = ComplianceStatus.FAIL
        elif any(v.risk_level == RiskLevel.RISK_WARNING for v in violations):
            status = ComplianceStatus.FLAGGED
        else:
            status = ComplianceStatus.PASS

        return EvaluationResult(
            status=status,
            target_distribution_type=dist_type,
            is_commercial=comm_flag,
            components=list(components),
            findings=findings,
            violations=violations,
            inter_license_conflicts=inter_conflicts,
        )

    def _get_alternative_hint(self, comp_name: str) -> str:
        lowered = comp_name.lower()
        if lowered in self.recommended_alternatives:
            return f" such as {self.recommended_alternatives[lowered]}"
        for key, hint in self.recommended_alternatives.items():
            if key in lowered or lowered in key:
                return f" such as {hint}"
        return ""

    def _evaluate_single_component(
        self,
        comp: DiscoveredComponent,
        lic_info: LicenseInfo,
        dist_type: str,
        is_commercial: bool,
    ) -> LicenseViolation:
        canonical = lic_info.canonical_id
        alt_hint = self._get_alternative_hint(comp.name)

        for rule in self.rules:
            rule_licenses: list[str] = rule.get("licenses", [])
            rule_dists: list[str] = rule.get("distribution_types", [])
            comm_only: bool = bool(rule.get("commercial_only", False))

            if canonical not in rule_licenses:
                continue
            if dist_type not in rule_dists:
                continue
            if comm_only and not is_commercial:
                continue

            explanation = str(rule["explanation_template"]).format(
                name=comp.name,
                license=canonical,
                raw_license=comp.raw_license,
                distribution_type=dist_type,
            )
            # Enrich GPL-2.0-only explanation with patent clause note
            if canonical == "GPL-2.0-only":
                explanation += (
                    " Additionally, GPL-2.0-only lacks an explicit patent grant and causes "
                    "Patent Clause Friction when combined with Apache-2.0 components."
                )

            remediation = str(rule["remediation_template"]).format(
                name=comp.name,
                license=canonical,
                raw_license=comp.raw_license,
                distribution_type=dist_type,
                alternative_hint=alt_hint,
            )

            return LicenseViolation(
                component=comp,
                rule_id=str(rule["rule_id"]),
                risk_level=RiskLevel(str(rule["risk_level"])),
                flag_type=str(rule["flag_type"]),
                legal_explanation=explanation,
                remediation_advice=remediation,
                obligations=list(rule.get("obligations", [])),
                license_info=lic_info,
            )

        # Fallback for non-commercial licenses in non-commercial context -> compliant with notice
        if lic_info.category == LicenseCategory.NON_COMMERCIAL and not is_commercial:
            return LicenseViolation(
                component=comp,
                rule_id="RULE-OK-NONCOMMERCIAL-RESEARCH",
                risk_level=RiskLevel.RISK_COMPLIANT,
                flag_type="NON_COMMERCIAL_COMPLIANT_IN_RESEARCH",
                legal_explanation=(
                    f"Component '{comp.name}' ({canonical}) restricts commercial use, "
                    f"which is compliant in the current non-commercial ({dist_type}) context."
                ),
                remediation_advice="Ensure usage remains strictly non-commercial and retain attribution notices.",
                obligations=["Maintain non-commercial usage boundary", "Retain attribution notices"],
                license_info=lic_info,
            )

        # Fallback for GPL in OPEN_SOURCE context -> warning/compliant note on copyleft compatibility
        if lic_info.category in (LicenseCategory.STRONG_COPYLEFT, LicenseCategory.NETWORK_COPYLEFT) and dist_type == DeploymentMode.OPEN_SOURCE.value:
            return LicenseViolation(
                component=comp,
                rule_id="RULE-WARN-COPYLEFT-OSS",
                risk_level=RiskLevel.RISK_WARNING,
                flag_type="COPYLEFT_CONTAMINATION",
                legal_explanation=(
                    f"Component '{comp.name}' ({canonical}) is a copyleft dependency in an OPEN_SOURCE "
                    f"project. The repository's outbound license must be compatible with {canonical}."
                ),
                remediation_advice=(
                    f"Ensure your project's outbound license is {canonical}-compatible, or replace '{comp.name}' "
                    f"with a permissive library{alt_hint}."
                ),
                obligations=[f"License combined open-source work under {canonical}-compatible terms"],
                license_info=lic_info,
            )

        return LicenseViolation(
            component=comp,
            rule_id="RULE-WARN-UNMAPPED",
            risk_level=RiskLevel.RISK_WARNING,
            flag_type="UNKNOWN_LICENSE",
            legal_explanation=(
                f"Component '{comp.name}' ({canonical}) could not be automatically cleared for {dist_type}."
            ),
            remediation_advice=f"Manually review license terms for '{comp.name}'.",
            obligations=["Verify license terms with legal counsel"],
            license_info=lic_info,
        )

    def _evaluate_inter_license_conflicts(
        self, components: list[DiscoveredComponent]
    ) -> list[LicenseViolation]:
        """Detect inter-license incompatibilities across the component graph (e.g. Apache-2.0 vs GPL-2.0-only)."""
        conflicts: list[LicenseViolation] = []
        by_license: dict[str, list[DiscoveredComponent]] = {}
        for comp in components:
            by_license.setdefault(comp.normalized_license, []).append(comp)

        for rule in self.inter_license_rules:
            lic_a = str(rule["license_a"])
            lic_b = str(rule["license_b"])
            comps_a = by_license.get(lic_a, [])
            comps_b = by_license.get(lic_b, [])

            if comps_a and comps_b:
                names_a = ", ".join(c.name for c in comps_a)
                names_b = ", ".join(c.name for c in comps_b)
                explanation = str(rule["explanation"]).format(
                    components_a=names_a,
                    components_b=names_b,
                )
                remediation = str(rule["remediation"]).format(
                    components_a=names_a,
                    components_b=names_b,
                )
                primary_comp = comps_b[0]
                conflicts.append(
                    LicenseViolation(
                        component=primary_comp,
                        rule_id=str(rule["conflict_id"]),
                        risk_level=RiskLevel(str(rule["risk_level"])),
                        flag_type=str(rule["flag_type"]),
                        legal_explanation=explanation,
                        remediation_advice=remediation,
                        obligations=[
                            "Resolve Apache-2.0 Section 3 patent termination vs GPL-2.0-only Section 6 incompatibility"
                        ],
                        license_info=classify_license(primary_comp.normalized_license),
                    )
                )
        return conflicts
