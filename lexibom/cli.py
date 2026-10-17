"""CLI entry point and project scanner orchestration for LexiBOM."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from lexibom import __version__
from lexibom.legal.evaluator import ComplianceEvaluator, ComplianceStatus, EvaluationResult
from lexibom.legal.taxonomy import LICENSE_CATALOG, classify_license, normalize_license
from lexibom.parsers.base import BaseParser, DiscoveredComponent
from lexibom.parsers.ml_model_parser import MLModelParser
from lexibom.parsers.node_parser import NodeDependencyParser
from lexibom.parsers.python_parser import PythonDependencyParser
from lexibom.reporters.json_export import JsonComplianceReporter
from lexibom.reporters.markdown import MarkdownNoticeReporter
from lexibom.reporters.terminal import TerminalReporter

app = typer.Typer(
    name="lexibom",
    help="LexiBOM: Open-Source & AI Model Weight License Compliance Scanner.",
    add_completion=False,
    no_args_is_help=True,
)

_GENERIC_VERSIONS: frozenset[str] = frozenset({"latest", "main", "*", "unknown", "weights", ""})
_LOCKFILE_NAMES: frozenset[str] = frozenset({"package-lock.json", "pipfile.lock"})


class ProjectScanner:
    """Orchestrates dual scanning across code dependencies (Python, Node) and AI/ML artifacts."""

    def __init__(self, parsers: list[BaseParser] | None = None) -> None:
        self.parsers: list[BaseParser] = parsers or [
            PythonDependencyParser(),
            NodeDependencyParser(),
            MLModelParser(),
        ]

    def scan(self, target_path: Path) -> list[DiscoveredComponent]:
        """Scan target_path across all registered parsers and merge cross-manifest duplicates."""
        resolved = target_path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        all_components: list[DiscoveredComponent] = []
        for parser in self.parsers:
            all_components.extend(parser.scan_directory(resolved))

        # Deduplicate and merge by (component_type, canonical lowercase name)
        merged_by_key: dict[tuple[str, str], DiscoveredComponent] = {}
        for comp in all_components:
            canon_name = comp.name.strip().lower()
            if comp.component_type.value == "python":
                import re

                canon_name = re.sub(r"[-_.]+", "-", canon_name)
            key = (comp.component_type.value, canon_name)
            if key not in merged_by_key:
                comp.metadata.setdefault("source_files", [comp.source_file])
                merged_by_key[key] = comp
                continue

            existing = merged_by_key[key]
            source_files: list[str] = existing.metadata.setdefault(
                "source_files", [existing.source_file]
            )
            if comp.source_file not in source_files:
                source_files.append(comp.source_file)

            # Prefer pinned lockfile versions or concrete versions over generic placeholders
            comp_is_lock = Path(comp.source_file).name.lower() in _LOCKFILE_NAMES
            if (
                existing.version in _GENERIC_VERSIONS
                and comp.version not in _GENERIC_VERSIONS
            ) or (comp_is_lock and comp.version not in _GENERIC_VERSIONS):
                existing.version = comp.version

            # Prefer verified license over UNKNOWN
            if (
                existing.normalized_license == "UNKNOWN"
                and comp.normalized_license != "UNKNOWN"
            ):
                existing.raw_license = comp.raw_license
                existing.normalized_license = comp.normalized_license
                existing.copyright_holder = comp.copyright_holder

        return list(merged_by_key.values())


def run_scan_pipeline(
    target_path: Path,
    context: str = "commercial-saas",
    is_commercial: bool | None = None,
) -> EvaluationResult:
    """Run the full LexiBOM discovery and legal evaluation pipeline on target_path."""
    scanner = ProjectScanner()
    components = scanner.scan(target_path)
    evaluator = ComplianceEvaluator()
    dist_type, comm_flag = evaluator.resolve_context(context, is_commercial)
    return evaluator.evaluate(
        components=components,
        target_distribution_type=dist_type,
        is_commercial=comm_flag,
    )


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show LexiBOM version and exit.",
        is_eager=True,
    ),
) -> None:
    """LexiBOM CLI root callback."""
    if version:
        typer.echo(f"LexiBOM v{__version__}")
        raise typer.Exit(code=0)


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        help="Path to the target project directory or manifest file to inspect.",
    ),
    context: str = typer.Option(
        "commercial-saas",
        "--context",
        "-c",
        help=(
            "Target deployment context preset (commercial-saas, proprietary-distributed, "
            "open-source, research-noncommercial) or mode (SAAS_HOSTED, PROPRIETARY_DISTRIBUTED, OPEN_SOURCE)."
        ),
    ),
    commercial: bool | None = typer.Option(
        None,
        "--commercial/--non-commercial",
        help="Explicitly override whether the target deployment is commercial.",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory where compliance-report.json and THIRD_PARTY_NOTICES.md will be written.",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="Custom file path for the JSON compliance report (default: compliance-report.json).",
    ),
    notices_out: Path | None = typer.Option(
        None,
        "--notices-out",
        help="Custom file path for THIRD_PARTY_NOTICES.md (default: THIRD_PARTY_NOTICES.md).",
    ),
    no_export: bool = typer.Option(
        False,
        "--no-export",
        help="Disable writing compliance-report.json and THIRD_PARTY_NOTICES.md to disk.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with code 1 if status is FAIL (critical legal violations found).",
    ),
) -> None:
    """Inspect a project directory, map code & ML model licenses, and run a legal compliance audit."""
    console = Console(width=128, legacy_windows=False)
    try:
        result = run_scan_pipeline(target_path=path, context=context, is_commercial=commercial)
    except ValueError as exc:
        console.print(f"[bold red]Configuration Error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    except FileNotFoundError as exc:
        console.print(f"[bold red]File Error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    reporter = TerminalReporter(console=console)
    reporter.render(result, project_path=path.as_posix())

    if not no_export:
        base_dir = output_dir if output_dir is not None else Path.cwd()
        resolved_json = json_out if json_out is not None else (base_dir / "compliance-report.json")
        resolved_notices = (
            notices_out if notices_out is not None else (base_dir / "THIRD_PARTY_NOTICES.md")
        )

        json_written = JsonComplianceReporter.write_report(
            result, resolved_json, project_path=path.as_posix()
        )
        notices_written = MarkdownNoticeReporter.write_report(result, resolved_notices)

        console.print(
            f"[bold cyan]Reports Generated:[/]\n"
            f"  - JSON SBOM & Audit Report: [underline]{json_written.as_posix()}[/]\n"
            f"  - Third-Party Attribution Notices: [underline]{notices_written.as_posix()}[/]"
        )

    if strict and result.status == ComplianceStatus.FAIL:
        raise typer.Exit(code=1)


@app.command("normalize")
def normalize_command(
    license_str: str = typer.Argument(..., help="Raw license string to normalize and classify."),
) -> None:
    """Normalize a raw license string into its canonical SPDX or ML taxonomy identifier."""
    console = Console(width=128, legacy_windows=False)
    canonical = normalize_license(license_str)
    info = classify_license(canonical)
    console.print(f"[bold]Raw Input:[/] {license_str}")
    console.print(f"[bold]Canonical ID:[/] [cyan]{info.canonical_id}[/]")
    console.print(f"[bold]Display Name:[/] {info.name}")
    console.print(f"[bold]Category:[/] [magenta]{info.category.value}[/]")
    console.print(f"[bold]Allows Commercial:[/] {info.allows_commercial}")
    console.print(f"[bold]Patent Grant:[/] {info.has_patent_grant}")
    console.print(f"[bold]Behavioral Restrictions:[/] {info.has_behavioral_restrictions}")


@app.command("taxonomy")
def taxonomy_command() -> None:
    """List all supported canonical code and AI/ML licenses in the LexiBOM taxonomy."""
    from rich.table import Table

    console = Console(width=128, legacy_windows=False)
    table = Table(title="LexiBOM Canonical License Taxonomy", header_style="bold cyan")
    table.add_column("Canonical ID", style="bold")
    table.add_column("Name")
    table.add_column("Category", style="magenta")
    table.add_column("Commercial")
    table.add_column("Patent Grant")
    table.add_column("Behavioral")

    for lic in LICENSE_CATALOG.values():
        table.add_row(
            lic.canonical_id,
            lic.name,
            lic.category.value,
            "Yes" if lic.allows_commercial else "No",
            "Yes" if lic.has_patent_grant else "No",
            "Yes" if lic.has_behavioral_restrictions else "No",
        )
    console.print(table)


def main() -> None:
    """CLI entrypoint for Poetry script execution."""
    app()


if __name__ == "__main__":
    main()
