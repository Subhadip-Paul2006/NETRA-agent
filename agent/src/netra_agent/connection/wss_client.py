"""NETRA Host Agent Outbound WSS Client with Exponential Backoff and REST Fallback."""

import asyncio
import contextlib
import json
import time
import uuid
from collections.abc import Callable
from typing import Any

import websockets
from netra_shared.crypto import construct_canonical_payload, sign_payload
from websockets.exceptions import WebSocketException

from netra_agent.auth.keyring import load_device_private_key
from netra_agent.connection.rest_client import AgentRESTClient


class AgentWSSClient:
    """Persistent outbound WSS client with Ed25519 handshake and REST fallback."""

    def __init__(
        self,
        server_url: str,
        device_id: str,
        max_reconnect_attempts: int = 5,
        base_backoff_sec: float = 1.0,
        max_backoff_sec: float = 30.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.max_reconnect_attempts = max_reconnect_attempts
        self.base_backoff_sec = base_backoff_sec
        self.max_backoff_sec = max_backoff_sec
        self.ws_url = self._convert_to_ws_url(server_url)
        self.rest_fallback_client = AgentRESTClient(server_url, device_id)
        self.is_connected = False
        self.should_stop = False

    def _convert_to_ws_url(self, server_url: str) -> str:
        """Convert http/https scheme to ws/wss scheme."""
        url = server_url.rstrip("/")
        if url.startswith("https://"):
            return "wss://" + url[8:] + "/agent/connect"
        if url.startswith("http://"):
            return "ws://" + url[7:] + "/agent/connect"
        return url + "/agent/connect"

    def _build_handshake_headers(self) -> dict[str, str]:
        """Construct Ed25519 signed security headers for WSS handshake."""
        private_key_bytes = load_device_private_key()
        if not private_key_bytes:
            raise RuntimeError(
                "Failed to load local device Ed25519 private key from OS protected keyring"
            )

        timestamp_str = str(time.time())
        nonce = str(uuid.uuid4())
        request_id = f"req_{uuid.uuid4().hex[:16]}"

        canonical_payload = construct_canonical_payload(
            method="GET",
            path="/api/v1/agent/connect",
            timestamp=timestamp_str,
            nonce=nonce,
            request_id=request_id,
            body=b"",
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

    async def connect_and_run(
        self,
        on_message_callback: Callable[[dict[str, Any]], None] | None = None,
        single_turn: bool = False,
    ) -> None:
        """Connect to WSS Gateway with exponential backoff and REST polling fallback."""
        attempt = 0

        while not self.should_stop:
            try:
                headers = self._build_handshake_headers()
                async with websockets.connect(
                    self.ws_url,
                    additional_headers=headers,
                    ping_interval=30,
                    ping_timeout=10,
                ) as ws:
                    self.is_connected = True
                    attempt = 0

                    # Receive welcome message
                    welcome_raw = await ws.recv()
                    welcome_msg = json.loads(welcome_raw)
                    if on_message_callback:
                        on_message_callback(welcome_msg)

                    if single_turn:
                        await ws.close()
                        self.is_connected = False
                        break

                    while not self.should_stop:
                        msg_raw = await ws.recv()
                        msg = json.loads(msg_raw)
                        if on_message_callback:
                            on_message_callback(msg)

            except (WebSocketException, Exception):  # noqa: PERF203
                self.is_connected = False
                attempt += 1

                if single_turn:
                    break

                if attempt >= self.max_reconnect_attempts:
                    # Switch to REST Polling Fallback
                    with contextlib.suppress(Exception):
                        self.rest_fallback_client.poll_tasks()

                # Exponential backoff algorithm
                backoff = min(self.base_backoff_sec * (2 ** (attempt - 1)), self.max_backoff_sec)
                await asyncio.sleep(backoff)

    def stop(self) -> None:
        """Signal client to stop connection loop."""
        self.should_stop = True
