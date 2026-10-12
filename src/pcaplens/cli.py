"""Offline Typer CLI; follow emits stream hashes and gap metadata, never bytes."""

from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
import click
from rich.console import Console
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from pcaplens import __version__
from pcaplens.analysis.summary import analyze
from pcaplens.analysis.timeline import plot
from pcaplens.detect import arp_spoof, beaconing, cleartext, dns_anomaly, scan
from pcaplens.limits import Limits
from pcaplens.output import csv_out, html_report, json_out, table
from pcaplens.output.sanitize import text
from pcaplens.settings import Settings
from pcaplens.output.redact import redact

app = typer.Typer(
    pretty_exceptions_enable=False,
    help="Offline authorized capture analysis. No live capture or decryption.",
)
console = Console(stderr=True)


class Format(str, Enum):
    json = "json"
    csv = "csv"
    html = "html"
    table = "table"


class Policy(str, Enum):
    first = "first"
    last = "last"
    reject = "reject"


def register(name: str) -> None:
    @app.command(name, help=f"Offline {name}; metadata and hashes only.")
    def command(
        capture: Annotated[Path, typer.Argument(dir_okay=False)],
        limits: Annotated[Path | None, typer.Option(help="Validated limits YAML")] = None,
        settings: Annotated[
            Path | None, typer.Option(help="Validated analysis settings YAML")
        ] = None,
        expression: Annotated[str | None, typer.Option(help="Packet filter expression")] = None,
        format: Annotated[Format, typer.Option()] = Format.json,
        output: Annotated[Path | None, typer.Option(help="Exclusive-create output file")] = None,
        checksum: Annotated[bool | None, typer.Option()] = None,
        overlap: Annotated[Policy | None, typer.Option()] = None,
        no_redact: Annotated[
            bool, typer.Option(help="Explicitly expose sensitive metadata")
        ] = False,
        anonymize: Annotated[bool | None, typer.Option()] = None,
        progress: Annotated[bool, typer.Option(help="Show analysis activity on stderr")] = False,
        timeline_plot: Annotated[Path | None, typer.Option(help="Save I/O plot (PNG)")] = None,
    ) -> None:
        try:
            configuration = Limits.load(limits)
            defaults = Settings.load(settings)
            arguments: dict[str, Any] = {
                "checksum": defaults.checksum if checksum is None else checksum,
                "overlap": defaults.overlap_policy if overlap is None else overlap.value,
                "expression": expression,
                "redaction": defaults.redact and not no_redact,
                "anonymize": defaults.anonymize if anonymize is None else anonymize,
            }
            if name == "filter" and not expression:
                raise ValueError("filter requires --expression")
            if progress:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("{task.description}"),
                    TextColumn("{task.completed:.0f} packets processed"),
                    console=console,
                    transient=True,
                ) as display:
                    task = display.add_task("Analyzing offline capture", total=None)

                    def update(count: int) -> None:
                        display.update(task, completed=count)

                    result = analyze(capture, configuration, on_progress=update, **arguments)
            else:
                result = analyze(capture, configuration, **arguments)
            section: Any = result
            result["scan"]["settings"] = defaults.model_dump()
            if name in ("summary", "flows", "dns", "http", "tls", "hierarchy", "talkers"):
                section = result[name]
                if name == "summary":
                    section = {**section, "protocol_counts": result["protocols"]}
            elif name == "follow":
                section = [
                    {"a": flow["a"], "b": flow["b"], "streams": flow["streams"]}
                    for flow in result["flows"]
                    if flow["streams"]
                ]
            elif name == "detect":
                section = {
                    "alerts": scan.detect(result, defaults.scan_ports, defaults.scan_window_seconds)
                    + dns_anomaly.detect(result, defaults.dns_length, defaults.dns_entropy)
                    + beaconing.detect(result, defaults.beacon_min_intervals, defaults.beacon_cv)
                    + arp_spoof.detect(result)
                    + cleartext.detect(result),
                    "data_suppressed": result["suppressed"],
                    "warnings": result["warnings"],
                }
            # Every export includes scan metadata and diagnostics, even selected sections.
            document = (
                result
                if section is result
                else {
                    "scan": result["scan"],
                    "warnings": result["warnings"],
                    "suppressed": result["suppressed"],
                    name: section,
                }
            )
            if timeline_plot:
                if timeline_plot.exists():
                    raise ValueError("Refusing to overwrite an existing timeline plot")
                plot(result["timeline"], timeline_plot)
            if name == "report":
                format = Format.html
            if format == Format.table:
                if output:
                    raise ValueError(
                        "Table output is terminal-only; select json/csv/html for a file"
                    )
                rows = (
                    section
                    if isinstance(section, list)
                    else [{"field": key, "value": value} for key, value in section.items()]
                )
                Console().print(table.render(rows))
            else:
                if format == Format.csv:
                    # Envelope rows preserve settings and warnings in CSV too.
                    content = csv_out.render(
                        [{"section": key, "value": value} for key, value in document.items()]
                    )
                else:
                    content = (
                        html_report.render(document)
                        if format == Format.html
                        else json_out.render(document)
                    )
                if output:
                    with output.open("x", encoding="utf-8", newline="") as destination:
                        destination.write(content)
                else:
                    typer.echo(content, nl=False)
            if result["warnings"]["count"]:
                console.print(
                    Text(
                        f"Recorded {result['warnings']['count']} warnings; results may be partial."
                    )
                )
                raise typer.Exit(2)
        except (ValueError, OSError) as error:
            console.print(Text(text(str(redact(f"pcaplens: {error}")))))
            raise typer.Exit(1) from error


for _name in (
    "summary",
    "flows",
    "dns",
    "http",
    "tls",
    "follow",
    "filter",
    "export",
    "report",
    "detect",
    "hierarchy",
    "talkers",
):
    register(_name)


@app.command()
def version() -> None:
    """Print the installed tool version."""
    typer.echo(__version__)


def main() -> None:
    """Sanitize framework errors too, including hostile command-line filenames."""
    try:
        code = app(standalone_mode=False)
    except click.ClickException as error:
        typer.echo(text(str(redact(error.format_message()))), err=True)
        raise SystemExit(error.exit_code) from error
    except click.Abort as error:
        typer.echo("Aborted", err=True)
        raise SystemExit(130) from error
    if isinstance(code, int):
        raise SystemExit(code)
