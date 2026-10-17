"""Rich terminal reporter for LexiBOM legal compliance audits."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lexibom.legal.evaluator import ComplianceStatus, EvaluationResult, RiskLevel


def _risk_badge(risk: RiskLevel) -> Text:
    if risk == RiskLevel.RISK_CRITICAL:
        return Text("CRITICAL", style="bold white on red")
    if risk == RiskLevel.RISK_WARNING:
        return Text("WARNING", style="bold black on yellow")
    return Text("COMPLIANT", style="bold white on green")


def _status_badge(status: ComplianceStatus) -> str:
    if status == ComplianceStatus.FAIL:
        return "[bold white on red] FAIL (CRITICAL VIOLATIONS DETECTED) [/]"
    if status == ComplianceStatus.FLAGGED:
        return "[bold black on yellow] FLAGGED (LEGAL REVIEW / OBLIGATIONS REQUIRED) [/]"
    return "[bold white on green] PASS (COMPLIANT) [/]"


class TerminalReporter:
    """Renders LexiBOM scan results and legal violations using Rich tables and panels."""

    def __init__(self, console: Console | None = None) -> None:
        if console is not None:
            self.console = console
        else:
            self.console = Console(width=128, legacy_windows=False)

    def render(self, result: EvaluationResult, project_path: str = ".") -> None:
        """Render the complete executive summary, component BOM table, and violation details."""
        comm_label = "COMMERCIAL" if result.is_commercial else "NON-COMMERCIAL (RESEARCH)"
        summary_lines = [
            f"[bold]Target Project:[/] {project_path}",
            f"[bold]Deployment Mode:[/] [cyan]{result.target_distribution_type}[/] ({comm_label})",
            f"[bold]Audit Status:[/] {_status_badge(result.status)}",
            "",
            (
                f"[bold]Discovered Components:[/] {len(result.components)}   "
                f"[bold red]Critical:[/] {result.critical_count}   "
                f"[bold yellow]Warnings:[/] {result.warning_count}   "
                f"[bold green]Compliant:[/] {result.compliant_count}"
            ),
        ]
        self.console.print(
            Panel(
                "\n".join(summary_lines),
                title="[bold cyan]LexiBOM Legal Compliance & AI Model Weight Audit[/]",
                border_style="cyan",
                expand=False,
            )
        )

        # Component Bill of Materials Table
        bom_table = Table(
            title="Discovered Code Libraries & AI/ML Model Artifacts",
            show_lines=True,
            header_style="bold magenta",
            expand=True,
        )
        bom_table.add_column("Component / Model", style="bold", ratio=3)
        bom_table.add_column("Version", ratio=1)
        bom_table.add_column("Type", style="cyan", ratio=1)
        bom_table.add_column("Raw License", ratio=2)
        bom_table.add_column("Canonical ID", style="bold", ratio=2)
        bom_table.add_column("Category", ratio=2)
        bom_table.add_column("Risk Tier", justify="center", ratio=1)
        bom_table.add_column("Source", style="dim", ratio=2)

        for finding in result.findings:
            if finding.rule_id.startswith("CONFLICT-"):
                continue
            comp = finding.component
            cat_str = finding.license_info.category.value if finding.license_info else "UNKNOWN"
            bom_table.add_row(
                comp.name,
                comp.version,
                comp.component_type.value,
                comp.raw_license,
                comp.normalized_license,
                cat_str,
                _risk_badge(finding.risk_level),
                comp.source_file,
            )

        self.console.print(bom_table)

        # Violations & Legal Explanations
        if result.violations:
            self.console.print("\n[bold underline]Legal Compatibility Violations & Risk Notes[/]\n")
            for idx, violation in enumerate(result.violations, start=1):
                border = "red" if violation.risk_level == RiskLevel.RISK_CRITICAL else "yellow"
                risk_tag = (
                    "[bold red]RISK_CRITICAL[/]"
                    if violation.risk_level == RiskLevel.RISK_CRITICAL
                    else "[bold yellow]RISK_WARNING[/]"
                )
                obligations_text = "\n".join(
                    f"  - {ob}" for ob in violation.obligations
                ) or "  - None specified"
                body = (
                    f"[bold]Component:[/] {violation.component.name} ({violation.component.version}) "
                    f"[{violation.component.component_type.value}]\n"
                    f"[bold]License:[/] {violation.component.normalized_license} "
                    f"(raw: '{violation.component.raw_license}')\n"
                    f"[bold]Source:[/] {violation.component.source_file}\n"
                    f"[bold]Flag Type:[/] {violation.flag_type} ({violation.rule_id})\n\n"
                    f"[bold]Legal Explanation:[/]\n{violation.legal_explanation}\n\n"
                    f"[bold]Actionable Remediation:[/]\n[green]{violation.remediation_advice}[/]\n\n"
                    f"[bold]Mandatory Obligations:[/]\n{obligations_text}"
                )
                self.console.print(
                    Panel(
                        body,
                        title=f"#{idx} {risk_tag} -- {violation.component.name} [{violation.flag_type}]",
                        border_style=border,
                    )
                )
        else:
            self.console.print(
                "\n[bold green]No legal compatibility violations or warnings detected.[/]\n"
            )
