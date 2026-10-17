"""Parsers for Python dependencies, Node.js dependencies, and AI/ML model artifacts."""

from lexibom.parsers.base import BaseParser, ComponentType, DiscoveredComponent
from lexibom.parsers.ml_model_parser import MLModelParser, resolve_model_license
from lexibom.parsers.node_parser import NodeDependencyParser, resolve_node_package_license
from lexibom.parsers.python_parser import (
    PythonDependencyParser,
    resolve_python_package_license,
)

__all__ = [
    "BaseParser",
    "ComponentType",
    "DiscoveredComponent",
    "MLModelParser",
    "NodeDependencyParser",
    "PythonDependencyParser",
    "resolve_model_license",
    "resolve_node_package_license",
    "resolve_python_package_license",
]
