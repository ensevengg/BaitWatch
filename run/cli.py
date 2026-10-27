from pathlib import Path
from typing import Annotated

import typer

from run.sandbox import SandboxConfig, detonate

app = typer.Typer(help="BaitWatch RUN foundation. Sandbox execution is not a full scan.")


@app.command()
def sandbox(
    repo: Annotated[Path, typer.Argument(help="Repository copied into the cage.")],
    command: Annotated[
        list[str], typer.Argument(help="Container argv after --; use an explicit sh -c if desired.")
    ],
    image: Annotated[
        str, typer.Option(help="Trusted image; must already exist locally.")
    ] = "alpine:3.20",
    timeout: Annotated[float, typer.Option(min=0.1, help="Execution deadline in seconds.")] = 20,
) -> None:
    """Print RUN evidence; missing components always remain incomplete."""
    evidence = detonate(repo, command, config=SandboxConfig(image=image, timeout_seconds=timeout))
    typer.echo(evidence.model_dump_json(indent=2))
    # Exit 0 is reserved for a complete scan. Neither 2 (incomplete) nor 3 (error) permits an agent.
    raise typer.Exit(3 if evidence.errors else 2)


@app.command()
def version() -> None:
    """Show the foundation version."""
    typer.echo("baitwatch 0.1.0 (RUN foundation)")
