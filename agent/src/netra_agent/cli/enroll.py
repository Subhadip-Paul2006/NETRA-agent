"""NETRA Agent Typer CLI Enrollment Command Module."""

import json
import platform
from pathlib import Path
from typing import Annotated

import httpx
import typer

from netra_agent.auth.keyring import get_or_create_device_keypair


def get_config_path() -> Path:
    """Get path to agent configuration file."""
    config_dir = Path.home() / ".netra"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "agent.json"


def enroll(
    code: Annotated[str, typer.Argument(help="Single-use device enrollment authorization code.")],
    server_url: Annotated[
        str,
        typer.Option(
            "--server-url",
            "-s",
            help="Target NETRA Central Security Engine API base URL.",
        ),
    ] = "http://localhost:4000/api/v1",
) -> None:
    """Enroll host machine with central security engine and register Ed25519 public key."""
    typer.echo("🔒 NETRA Agent Enrollment Initiated...")

    # 1. Obtain or generate local Ed25519 keypair in OS protected keyring
    try:
        _, public_key_hex = get_or_create_device_keypair()
        typer.echo("✔ Ed25519 keypair loaded from OS protected keyring.")
    except Exception as exc:
        typer.secho(f"✖ Failed to access OS protected keyring: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    # 2. Gather host machine telemetry
    hostname = platform.node() or "unknown-host"
    os_name = f"{platform.system()} {platform.release()}"[:50]
    arch = platform.machine()[:50]
    agent_version = "0.1.0"

    endpoint_url = f"{server_url.rstrip('/')}/agent/enroll"
    payload = {
        "code": code.strip(),
        "hostname": hostname,
        "os": os_name,
        "architecture": arch,
        "agent_version": agent_version,
        "public_key": public_key_hex,
    }

    typer.echo(f"🛰 Submitting enrollment request to {endpoint_url}...")

    # 3. Perform HTTP request to central engine
    try:
        with httpx.Client(timeout=10.0) as client:
            res = client.post(endpoint_url, json=payload)
    except Exception as exc:
        typer.secho(f"✖ Connection error: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    if res.status_code != 200:
        try:
            body = res.json()
            error_msg = body.get("error", {}).get("message", body.get("detail", res.text))
        except Exception:
            error_msg = res.text
        typer.secho(
            f"✖ Enrollment failed (HTTP {res.status_code}): {error_msg}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    data = res.json()
    device_id = data["device_id"]
    tenant_id = data["tenant_id"]

    # 4. Save local configuration
    config_file = get_config_path()
    config_data = {
        "device_id": device_id,
        "tenant_id": tenant_id,
        "server_url": server_url,
        "public_key": public_key_hex,
    }
    config_file.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

    typer.secho("✅ Enrollment successful!", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"   Device ID : {device_id}")
    typer.echo(f"   Tenant ID : {tenant_id}")
    typer.echo(f"   Config    : {config_file}")
