"""The fused `baitwatch` CLI: one scan, one verdict JSON, one human report.

Exit codes: 0 ALLOW, 4 FLAG, 5 BLOCK, 3 operational error. 1 and 2 stay
reserved for a crash or a usage error and never mean a verdict. No code
permits an agent to proceed on its own.
"""

import json
import re
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from run.cage import DEFAULT_IMAGE
from run.evidence import State, VerdictReport
from run.llm import LLMError, make_backend_with_fallback
from run.sandbox import SandboxConfig
from run.scan import run_scan

# The callback keeps `baitwatch scan` a subcommand; a single-command Typer app
# would otherwise flatten and parse "scan" as the repo path.
app = typer.Typer()


@app.callback()
def root() -> None:
    """BaitWatch scan: READ detection plus the RUN decoy cage, one verdict."""


# 1 and 2 stay reserved for a crash or a CLI usage error (click/Typer), so a
# verdict code is never ambiguous with either.
EXIT_CODES = {"ALLOW": 0, "FLAG": 4, "BLOCK": 5}
ERROR_EXIT = 3
_VERDICT_STYLES = {"ALLOW": "green", "FLAG": "yellow", "BLOCK": "red"}
# Snippets and paths inside the verdict come from the scanned repository;
# control characters are printed as code points so a repo cannot repaint
# the terminal report. C1 controls (U+0080-U+009F) are included: some
# terminals honor them as CSI/OSC introducers even in UTF-8 mode.
_CONTROL = re.compile(r"[\x00-\x1f\x7f\x80-\x9f\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]")


def _safe(text: str) -> str:
    return _CONTROL.sub(lambda match: f"<U+{ord(match.group()):04X}>", text)


def _human_report(report: VerdictReport, console: Console) -> None:
    run = report.run
    style = _VERDICT_STYLES[report.verdict]
    console.print(f"BaitWatch scan {report.verdict}", style=f"bold {style}")
    console.print(_safe(report.reason))
    if report.read.status is State.COMPLETE:
        # ReadEvidence carries only the status; the reason line above says why
        # the verdict is not ALLOW even on a complete READ.
        console.print("READ complete", style="dim")
    else:
        console.print(f"READ {report.read.status.value}: not complete, never allowed", style="dim")
    components = run.components.model_dump()
    outstanding = {
        name: State(state).value for name, state in components.items() if state != State.COMPLETE
    }
    parts = [f"RUN {run.status}"]
    parts.append("all components complete" if not outstanding else f"outstanding: {outstanding}")
    parts.append(f"{len(run.tool_log)} tool call(s)")
    parts.append(
        f"{len(run.dns_hits)} dns / {len(run.http_hits)} http / {len(run.tls_hits)} tls sink hit(s)"
    )
    parts.append(f"{len(run.honeytoken_hits)} honeytoken hit(s)")
    parts.append(f"{len(run.file_diffs)} file change(s) in the staged copy")
    console.print("; ".join(parts), style="dim")
    for error in run.errors[:5]:
        console.print(f"error {_safe(error.code)}: {_safe(error.message)}", style="dim")
    if len(run.errors) > 5:
        console.print(f"... +{len(run.errors) - 5} more errors", style="dim")


@app.command()
def scan(
    repo: Annotated[Path, typer.Argument(help="Repository copied into the scan cage.")],
    llm: Annotated[
        str,
        typer.Option(
            help="Decoy backend spec: scripted:PATH, ollama:MODEL, openai:BASE_URL#MODEL[#ENV_VAR]."
        ),
    ],
    image: Annotated[
        str, typer.Option(help="Trusted image; must already exist locally.")
    ] = DEFAULT_IMAGE,
    max_steps: Annotated[int, typer.Option(help="Maximum model turns and total tool calls.")] = 20,
    max_tokens: Annotated[int, typer.Option(help="Maximum total decoy tokens.")] = 100_000,
    max_seconds: Annotated[float, typer.Option(help="Maximum decoy wall seconds.")] = 120.0,
    llm_fallback: Annotated[
        str | None, typer.Option(help="Fallback backend spec if the primary fails.")
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Write the verdict JSON here instead of stdout.")
    ] = None,
) -> None:
    """Scan a repository; print the verdict JSON and a human report."""
    try:
        if not repo.is_dir():
            raise ValueError("repository must be an existing directory")
        if max_steps < 1:
            raise ValueError("max-steps must be positive")
        if max_tokens < 1:
            raise ValueError("max-tokens must be positive")
        if max_seconds <= 0:
            raise ValueError("max-seconds must be positive")
        config = SandboxConfig(
            image=image,
            decoy_seconds=max_seconds,
            decoy_max_tokens=max_tokens,
            decoy_max_seconds=max_seconds,
        )
        backend = make_backend_with_fallback(llm, llm_fallback)
    except (LLMError, ValueError) as exc:
        typer.echo(f"scan: {exc}", err=True)
        raise typer.Exit(ERROR_EXIT) from exc
    report = run_scan(repo, config=config, backend=backend, max_steps=max_steps)
    payload = json.dumps(report.model_dump(mode="json"), ensure_ascii=True, indent=2)
    if json_path is None:
        typer.echo(payload)
        _human_report(report, Console(stderr=True, markup=False, highlight=False))
    else:
        try:
            json_path.write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            typer.echo(f"scan: cannot write --json file: {exc}", err=True)
            raise typer.Exit(ERROR_EXIT) from exc
        _human_report(report, Console(markup=False, highlight=False))
    raise typer.Exit(EXIT_CODES[report.verdict])
