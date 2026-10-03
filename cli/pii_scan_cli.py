"""
PII Log Leak Detector — CLI Tool

Commands:
  scan <path>       Scan a directory for PII leaks in source files.
  scan-log <path>   Scan a single log file for PII leaks.
  fix <path>        Apply demo fixes to demo_vulnerable_app.
"""

import sys
import os
from pathlib import Path
from collections import defaultdict

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add project root to path so we can import backend modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.app.scanner.file_scanner import scan_directory
from backend.app.scanner.log_scanner import scan_log_file
from backend.app.services.fix_service import apply_demo_fix, DEMO_APP_PATH, FIXED_DIR, DEMO_FILES
from backend.app.models.findings import Severity, ScanResult

app = typer.Typer(
    name="pii-scan",
    help="PII Log Leak Detector — Find sensitive data before it reaches production logs.",
    add_completion=False,
)
console = Console()

SEVERITY_COLORS = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}


def _relative_file(filepath: str, root: str) -> str:
    """Return filepath relative to root if possible, else basename."""
    try:
        return str(Path(filepath).relative_to(Path(root).resolve()))
    except ValueError:
        return Path(filepath).name


def _print_findings_table(result: ScanResult, scan_root: str, verbose: bool = False) -> None:
    """Print a Rich table of findings from a ScanResult."""
    if result.total_findings == 0:
        console.print("\n[bold green]✓ No potential PII leaks detected.[/bold green]\n")
        return

    table = Table(
        title="Findings",
        show_header=True,
        header_style="bold white",
        border_style="bright_blue",
        show_lines=False,
    )
    table.add_column("Severity", style="", min_width=8)
    table.add_column("PII Type", style="", min_width=14)
    table.add_column("File", style="", min_width=24)
    table.add_column("Line", justify="right", min_width=4)
    table.add_column("Preview", style="", min_width=22)

    for finding in result.findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        rel_file = _relative_file(finding.file, scan_root)
        table.add_row(
            f"[{color}]{finding.severity.value}[/{color}]",
            finding.pii_type.value,
            rel_file,
            str(finding.line_number),
            finding.masked_value,
        )

    console.print()
    console.print(table)

    if verbose:
        console.print()
        for finding in result.findings:
            rel_file = _relative_file(finding.file, scan_root)
            console.print(
                f"  [dim]{rel_file}:{finding.line_number}[/dim] — {finding.detection_reason}"
            )

    console.print()
    leak_word = "leak" if result.total_findings == 1 else "leaks"
    console.print(
        f"[bold]{result.total_findings} potential PII {leak_word} detected "
        f"in {result.files_scanned} file{'s' if result.files_scanned != 1 else ''}.[/bold]"
    )
    console.print()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Directory to scan for PII leaks."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detection reason per finding."),
) -> None:
    """Scan a directory for PII leaks in source files."""
    resolved = str(Path(path).resolve())

    console.print(
        Panel(
            f"[bold]PII Log Leak Detector[/bold]\n[dim]Scanning:[/dim] {path}",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("Scanning files...", total=None)
        result = scan_directory(resolved)

    _print_findings_table(result, resolved, verbose=verbose)

    if result.total_findings > 0:
        console.print(f"Run [bold cyan]pii-scan fix {path}[/bold cyan] to review recommended fixes.\n")


@app.command(name="scan-log")
def scan_log(
    path: str = typer.Argument(..., help="Log file to scan for PII leaks."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detection reason per finding."),
) -> None:
    """Scan a single log file for PII leaks."""
    resolved = str(Path(path).resolve())
    log_dir = str(Path(resolved).parent)

    console.print(
        Panel(
            f"[bold]PII Log Leak Detector[/bold]\n[dim]Scanning log:[/dim] {path}",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("Scanning log file...", total=None)
        result = scan_log_file(resolved)

    _print_findings_table(result, log_dir, verbose=verbose)


@app.command()
def fix(
    path: str = typer.Argument(..., help="Path to demo_vulnerable_app directory."),
) -> None:
    """Apply demo fixes to demo_vulnerable_app (safe, controlled demo only)."""
    resolved = Path(path).resolve()

    # Safety guard — only allow demo_vulnerable_app
    if "demo_vulnerable_app" not in str(resolved):
        console.print(
            "[bold red]Error:[/bold red] The fix command only works on the demo_vulnerable_app directory.\n"
            "This restriction exists to prevent accidental modification of arbitrary files."
        )
        raise typer.Exit(code=1)

    console.print(
        Panel(
            "[bold]PII Log Leak Detector — Fix Mode[/bold]",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )

    # Initial scan to show current state
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("Scanning for current findings...", total=None)
        initial = scan_directory(str(resolved))

    console.print(
        f"\nCurrent scan: [bold]{initial.total_findings} finding{'s' if initial.total_findings != 1 else ''}[/bold] "
        f"in [bold]{initial.files_scanned}[/bold] file{'s' if initial.files_scanned != 1 else ''}.\n"
    )

    # Group findings by relative filename
    counts: dict[str, int] = defaultdict(int)
    for finding in initial.findings:
        rel = _relative_file(finding.file, str(resolved))
        counts[rel] += 1

    if counts:
        console.print("The following files will be updated with safe logging patterns:")
        for filename, count in sorted(counts.items()):
            console.print(f"  [cyan]•[/cyan] {filename}  ({count} finding{'s' if count != 1 else ''})")
        console.print()

    # Confirmation prompt
    confirmed = typer.confirm("Apply demo fixes?", default=False)
    if not confirmed:
        console.print("\n[yellow]Fix aborted.[/yellow]\n")
        raise typer.Exit(code=0)

    console.print("\nApplying fixes...\n")
    for filename in DEMO_FILES:
        src = FIXED_DIR / filename
        dst = resolved / filename
        if src.exists() and dst.exists():
            import shutil
            shutil.copy2(str(src), str(dst))
            console.print(f"  [bold green]✓[/bold green] {filename} updated")

    console.print("\nRe-scanning...\n")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("Re-scanning...", total=None)
        final = scan_directory(str(resolved))

    if final.total_findings == 0:
        console.print(
            Panel(
                f"[bold green]✓ No potential PII leaks detected.[/bold green]\n"
                f"  Files scanned: {final.files_scanned}\n"
                f"  Potential leaks: 0\n"
                f"  Scan completed successfully.",
                border_style="green",
                padding=(0, 2),
            )
        )
    else:
        console.print(
            f"[bold yellow]⚠ {final.total_findings} finding(s) remain after fix.[/bold yellow]"
        )
        _print_findings_table(final, str(resolved))

    console.print()


if __name__ == "__main__":
    app()
