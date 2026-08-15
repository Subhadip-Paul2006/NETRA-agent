"""Unit tests for AgentWSSClient and AgentRESTClient."""

from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from netra_agent.connection.rest_client import AgentRESTClient
from netra_agent.connection.wss_client import AgentWSSClient


def test_wss_client_url_conversion() -> None:
    """Verify conversion of http/https schemes to ws/wss schemes."""
    client_http = AgentWSSClient("http://localhost:4000/api/v1", "dev-12345")
    assert client_http.ws_url == "ws://localhost:4000/api/v1/agent/connect"

    client_https = AgentWSSClient("https://netra.example.com/api/v1", "dev-12345")
    assert client_https.ws_url == "wss://netra.example.com/api/v1/agent/connect"


@patch("netra_agent.connection.rest_client.load_device_private_key")
@patch("httpx.Client.get")
def test_rest_client_poll_tasks(mock_get: MagicMock, mock_load_key: MagicMock) -> None:
    """Verify AgentRESTClient constructs Ed25519 headers and polls tasks."""
    key = ed25519.Ed25519PrivateKey.generate()
    raw_key = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    mock_load_key.return_value = raw_key

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"success": True, "tasks": []}

    rest_client = AgentRESTClient("http://localhost:4000/api/v1", "dev-12345")
    response = rest_client.poll_tasks()

    assert response["success"] is True
    assert response["tasks"] == []
    mock_get.assert_called_once()
