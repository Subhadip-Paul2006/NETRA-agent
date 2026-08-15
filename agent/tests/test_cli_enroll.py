"""Integration tests for Typer CLI netra enroll command."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from netra_agent.cli.main import app

runner = CliRunner()


@patch("httpx.Client.post")
def test_cli_enroll_command_success(mock_post: MagicMock) -> None:
    """Verify netra enroll CLI command handles successful server response."""
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "device_id": "dev-12345-uuid",
        "tenant_id": "tnt-67890-uuid",
        "status": "ENROLLED",
    }

    result = runner.invoke(
        app, ["--server-url", "http://localhost:4000/api/v1", "NETRA-TEST-CODE-1234"]
    )

    assert result.exit_code == 0, f"CLI output: {result.output}"
    assert "Enrollment successful!" in result.stdout
    assert "dev-12345-uuid" in result.stdout
