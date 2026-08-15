"""NETRA Host Agent Fallback REST HTTP Client."""

import time
import uuid
from typing import Any

import httpx
from netra_shared.crypto import construct_canonical_payload, sign_payload

from netra_agent.auth.keyring import load_device_private_key


class AgentRESTClient:
    """Fallback HTTP REST client with Ed25519 signature authentication."""

    def __init__(self, server_url: str, device_id: str) -> None:
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id

    def _build_auth_headers(
        self, method: str, path: str, body_bytes: bytes = b""
    ) -> dict[str, str]:
        """Construct Ed25519 signed security headers for request."""
        private_key_bytes = load_device_private_key()
        if not private_key_bytes:
            raise RuntimeError(
                "Failed to load local device Ed25519 private key from OS protected keyring"
            )

        timestamp_str = str(time.time())
        nonce = str(uuid.uuid4())
        request_id = f"req_{uuid.uuid4().hex[:16]}"

        canonical_payload = construct_canonical_payload(
            method=method,
            path=path,
            timestamp=timestamp_str,
            nonce=nonce,
            request_id=request_id,
            body=body_bytes,
        )

        signature_bytes = sign_payload(private_key_bytes, canonical_payload)
        signature_hex = signature_bytes.hex()

        return {
            "X-NETRA-Device-ID": self.device_id,
            "X-NETRA-Timestamp": timestamp_str,
            "X-NETRA-Nonce": nonce,
            "X-NETRA-Request-ID": request_id,
            "X-NETRA-Signature": signature_hex,
        }

    def poll_tasks(self) -> dict[str, Any]:
        """Poll pending agent tasks via GET /api/v1/agent/tasks."""
        endpoint = f"{self.server_url}/agent/tasks"
        headers = self._build_auth_headers("GET", "/api/v1/agent/tasks")

        with httpx.Client(timeout=10.0) as client:
            res = client.get(endpoint, headers=headers)
            res.raise_for_status()
            return res.json()
