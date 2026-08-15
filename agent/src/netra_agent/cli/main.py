"""NETRA Agent Main Typer CLI Entrypoint."""

import typer

from netra_agent.cli.enroll import enroll

app = typer.Typer(
    name="netra",
    help="NETRA Host Security Agent CLI",
    add_completion=False,
)

app.command("enroll")(enroll)

if __name__ == "__main__":
    app()
