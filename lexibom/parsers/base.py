"""Abstract base classes and data models for LexiBOM dependency and artifact parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ComponentType(str, Enum):
    """Supported software and AI/ML component types."""

    PYTHON_PACKAGE = "python"
    NODE_PACKAGE = "node"
    ML_MODEL = "ml_model"


@dataclass
class DiscoveredComponent:
    """Represents a discovered software library or machine learning model artifact."""

    name: str
    version: str
    component_type: ComponentType
    raw_license: str
    normalized_license: str
    source_file: str
    copyright_holder: str = "Original Authors and Contributors"
    homepage: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def purl(self) -> str:
        """Return a canonical Package URL (pURL) identifier for SBOM generation."""
        ver = f"@{self.version}" if self.version and self.version not in ("*", "latest", "unknown") else ""
        if self.component_type == ComponentType.PYTHON_PACKAGE:
            return f"pkg:pypi/{self.name.lower()}{ver}"
        if self.component_type == ComponentType.NODE_PACKAGE:
            return f"pkg:npm/{self.name}{ver}"
        return f"pkg:ml/{self.name}{ver}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the discovered component into a JSON-compatible dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "component_type": self.component_type.value,
            "purl": self.purl,
            "raw_license": self.raw_license,
            "normalized_license": self.normalized_license,
            "source_file": self.source_file,
            "copyright_holder": self.copyright_holder,
            "homepage": self.homepage,
            "metadata": self.metadata,
        }


IGNORED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".eggs",
    }
)


class BaseParser(ABC):
    """Abstract parser interface for code dependencies and ML model artifacts."""

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Return True if this parser handles the given file path."""

    @abstractmethod
    def parse_file(
        self, file_path: Path, project_root: Path | None = None
    ) -> list[DiscoveredComponent]:
        """Parse a single manifest or artifact file and return discovered components."""

    def scan_directory(self, directory: Path) -> list[DiscoveredComponent]:
        """Recursively scan a directory for files supported by this parser."""
        discovered: list[DiscoveredComponent] = []
        root = directory.resolve()
        if root.is_file():
            if self.can_parse(root):
                return self.parse_file(root, project_root=root.parent)
            return []

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(root).parts[:-1]
            if any(part in IGNORED_DIRECTORIES for part in rel_parts):
                continue
            if self.can_parse(path):
                discovered.extend(self.parse_file(path, project_root=root))
        return discovered

    @staticmethod
    def format_source_path(file_path: Path, project_root: Path | None = None) -> str:
        """Format a file path relative to project_root using forward slashes."""
        if project_root is not None:
            try:
                return file_path.resolve().relative_to(project_root.resolve()).as_posix()
            except ValueError:
                pass
        return file_path.as_posix()
