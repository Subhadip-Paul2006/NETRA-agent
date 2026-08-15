"""NETRA Agent Persistent Outbound WSS Gateway Router."""

import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from netra_backend.database import get_session_factory
from netra_backend.logging import get_logger
from netra_backend.models import Device, DeviceCredential, NonceCache
from netra_shared.crypto import construct_canonical_payload, verify_ed25519_signature
from netra_shared.enums import DeviceCredentialStatus

logger = get_logger(__name__)

router = APIRouter(tags=["Agent WSS Gateway"])


class ConnectionManager:
    """Manages active Agent WSS Gateway persistent connections."""

    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        """Register active device WebSocket connection."""
        await websocket.accept()
        self.active_connections[device_id] = websocket
        logger.info("agent_wss_connected", device_id=device_id)

    def disconnect(self, device_id: str) -> None:
        """Remove active device WebSocket connection."""
        if device_id in self.active_connections:
            del self.active_connections[device_id]
            logger.info("agent_wss_disconnected", device_id=device_id)

    async def send_json(self, device_id: str, data: dict) -> bool:
        """Send JSON payload to connected device."""
        ws = self.active_connections.get(device_id)
        if ws:
            await ws.send_json(data)
            return True
        return False


manager = ConnectionManager()


@router.websocket("/agent/connect")
async def agent_wss_gateway(websocket: WebSocket) -> None:
    """Agent WSS Gateway Handshake with Ed25519 authentication and replay protection."""
    headers = websocket.headers
    query_params = websocket.query_params

    device_id = headers.get("X-NETRA-Device-ID") or query_params.get("device_id")
    timestamp_str = headers.get("X-NETRA-Timestamp") or query_params.get("timestamp")
    nonce = headers.get("X-NETRA-Nonce") or query_params.get("nonce")
    request_id = headers.get("X-NETRA-Request-ID") or query_params.get("request_id")
    signature = headers.get("X-NETRA-Signature") or query_params.get("signature")

    if not all([device_id, timestamp_str, nonce, request_id, signature]):
        logger.warning("wss_handshake_missing_headers", device_id=device_id)
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Missing Ed25519 security headers"
        )
        return

    assert timestamp_str is not None
    assert nonce is not None
    assert request_id is not None
    assert signature is not None
    assert device_id is not None

    # 1. Verify Timestamp Window (5-min expiration window)
    try:
        req_timestamp = float(timestamp_str)
        now_timestamp = time.time()
        if abs(now_timestamp - req_timestamp) > 300:
            logger.warning("wss_handshake_expired_timestamp", device_id=device_id)
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Expired timestamp window"
            )
            return
    except ValueError:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="Invalid timestamp format"
        )
        return

    session_factory = get_session_factory()
    async with session_factory() as db:
        # 2. Lookup Device and active Ed25519 public key
        stmt = (
            select(Device, DeviceCredential.public_key)
            .join(DeviceCredential, Device.id == DeviceCredential.device_id)
            .where(
                Device.id == device_id,
                Device.is_paired == True,  # noqa: E712
                DeviceCredential.status == DeviceCredentialStatus.ACTIVE,
            )
        )
        result = await db.execute(stmt)
        row = result.first()

        if not row:
            logger.warning("wss_handshake_device_not_found", device_id=device_id)
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Device unauthenticated or revoked"
            )
            return

        device, public_key_hex = row

        # 3. Replay Protection: Check NonceCache
        nonce_stmt = select(NonceCache).where(
            NonceCache.device_id == device_id,
            NonceCache.nonce == nonce,
        )
        nonce_result = await db.execute(nonce_stmt)
        if nonce_result.scalar_one_or_none():
            logger.warning("wss_handshake_replay_nonce_detected", device_id=device_id, nonce=nonce)
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Replay attack detected (duplicate nonce)",
            )
            return

        # 4. Verify Ed25519 Signature against Canonical Payload
        canonical_payload = construct_canonical_payload(
            method="GET",
            path="/api/v1/agent/connect",
            timestamp=timestamp_str,
            nonce=nonce,
            request_id=request_id,
            body=b"",
        )

        if not verify_ed25519_signature(public_key_hex, signature, canonical_payload):
            logger.warning("wss_handshake_invalid_signature", device_id=device_id)
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION, reason="Invalid Ed25519 signature"
            )
            return

        # Record nonce in NonceCache (durable database replay protection)
        nonce_entry = NonceCache(
            device_id=device_id,
            nonce=nonce,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        db.add(nonce_entry)

        # Update last_heartbeat_at
        device.last_heartbeat_at = datetime.now(UTC)
        await db.commit()

    # 5. Handshake Successful -> Accept Connection
    await manager.connect(device_id, websocket)

    try:
        await websocket.send_json(
            {
                "type": "connected",
                "device_id": device_id,
                "tenant_id": device.tenant_id,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

        # Main WSS Message Loop
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                        "timestamp": datetime.now(UTC).isoformat(),
                    }
                )
            else:
                logger.info("wss_message_received", device_id=device_id, msg_type=msg_type)

    except WebSocketDisconnect:
        manager.disconnect(device_id)
    except Exception as exc:
        logger.error("wss_gateway_connection_error", device_id=device_id, error=str(exc))
        manager.disconnect(device_id)
