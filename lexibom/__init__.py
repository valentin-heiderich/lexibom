"""LexiBOM: Open-Source & AI Model Weight License Compliance Scanner."""

__version__ = "0.1.0"

from lexibom.legal.evaluator import (
    ComplianceEvaluator,
    ComplianceStatus,
    EvaluationResult,
    LicenseViolation,
    RiskLevel,
)
from lexibom.legal.taxonomy import (
    LicenseCategory,
    LicenseInfo,
    LicenseTaxonomy,
    classify_license,
    normalize_license,
)
from lexibom.parsers.base import BaseParser, ComponentType, DiscoveredComponent

__all__ = [
    "__version__",
    "BaseParser",
    "ComponentType",
    "ComplianceEvaluator",
    "ComplianceStatus",
    "DiscoveredComponent",
    "EvaluationResult",
    "LicenseCategory",
    "LicenseInfo",
    "LicenseTaxonomy",
    "LicenseViolation",
    "RiskLevel",
    "classify_license",
    "normalize_license",
]
