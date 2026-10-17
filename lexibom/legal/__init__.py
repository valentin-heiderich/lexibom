"""Legal taxonomy and compatibility evaluation package for LexiBOM."""

from lexibom.legal.evaluator import (
    ComplianceEvaluator,
    ComplianceStatus,
    DeploymentMode,
    EvaluationResult,
    LicenseViolation,
    RiskLevel,
)
from lexibom.legal.taxonomy import (
    LICENSE_CATALOG,
    LicenseCategory,
    LicenseInfo,
    LicenseTaxonomy,
    classify_license,
    normalize_license,
)

__all__ = [
    "ComplianceEvaluator",
    "ComplianceStatus",
    "DeploymentMode",
    "EvaluationResult",
    "LICENSE_CATALOG",
    "LicenseCategory",
    "LicenseInfo",
    "LicenseTaxonomy",
    "LicenseViolation",
    "RiskLevel",
    "classify_license",
    "normalize_license",
]
