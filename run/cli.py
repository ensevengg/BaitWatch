import json
from pathlib import Path
from typing import Annotated

import typer

from run.cage import DEFAULT_IMAGE
from run.decoy import DECOY_CAGE_GRACE_SECONDS
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
    ] = DEFAULT_IMAGE,
    timeout: Annotated[
        float, typer.Option(help="Execution deadline in seconds (at least 0.1).")
    ] = 20,
) -> None:
    """Print RUN evidence; missing components always remain incomplete."""
    try:
        if not repo.is_dir():
            raise ValueError("repository must be an existing directory")
        if timeout < 0.1:
            raise ValueError("timeout must be at least 0.1")
        config = SandboxConfig(image=image, timeout_seconds=timeout)
    except ValueError as exc:
        typer.echo(f"sandbox: {exc}", err=True)
        raise typer.Exit(3) from exc
    evidence = detonate(repo, command, config=config)
    typer.echo(json.dumps(evidence.model_dump(mode="json"), ensure_ascii=True, indent=2))
    # Exit 0 is reserved for a complete scan. Neither 2 (incomplete) nor 3 (error) permits an agent.
    raise typer.Exit(3 if evidence.errors else 2)


@app.command()
def decoy(
    repo: Annotated[Path, typer.Argument(help="Repository copied into the cage.")],
    llm: Annotated[
        str,
        typer.Option(
            help="Backend spec: scripted:PATH, ollama:MODEL, openai:BASE_URL#MODEL[#ENV_VAR]."
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
) -> None:
    """Run the decoy agent; its tool calls execute only inside the cage."""
    from run.llm import LLMError, make_backend_with_fallback

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
            decoy_seconds=max_seconds + DECOY_CAGE_GRACE_SECONDS,
            decoy_max_tokens=max_tokens,
            decoy_max_seconds=max_seconds,
        )
        backend = make_backend_with_fallback(llm, llm_fallback)
    except (LLMError, ValueError) as exc:
        typer.echo(f"decoy: {exc}", err=True)
        raise typer.Exit(3) from exc
    evidence = detonate(
        repo,
        config=config,
        backend=backend,
        max_steps=max_steps,
    )
    typer.echo(json.dumps(evidence.model_dump(mode="json"), ensure_ascii=True, indent=2))
    contacts = (
        evidence.dns_hits or evidence.http_hits or evidence.tls_hits or evidence.honeytoken_hits
    )
    raise typer.Exit(
        3 if evidence.errors else 2 if evidence.status != "complete" or contacts else 0
    )


@app.command()
def version() -> None:
    """Show the foundation version."""
    typer.echo("baitwatch 0.1.0 (RUN foundation)")
