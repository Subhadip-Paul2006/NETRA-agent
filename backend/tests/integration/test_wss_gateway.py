"""Integration tests for backend WSS Gateway and Ed25519 handshake validation."""

import time
import uuid

import pytest
from httpx import AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from netra_backend.database import get_session_factory
from netra_backend.models import Device, DeviceCredential, Tenant
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus


@pytest.mark.asyncio
async def test_wss_handshake_success_and_heartbeat(client: AsyncClient, app) -> None:
    """Verify valid Ed25519 handshake, connection acceptance, and ping/pong heartbeat."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    pub_hex = pub_bytes.hex()

    async with session_factory() as db:
        tenant = Tenant(name="WSS Tenant", slug="wss-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="wss-host-01",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.flush()

        credential = DeviceCredential(
            device_id=device.id,
            public_key=pub_hex,
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(credential)
        await db.commit()

        device_id = device.id

    timestamp_str = str(time.time())
    nonce = str(uuid.uuid4())
    request_id = f"req_{uuid.uuid4().hex[:16]}"

    canonical = construct_canonical_payload(
        method="GET",
        path="/api/v1/agent/connect",
        timestamp=timestamp_str,
        nonce=nonce,
        request_id=request_id,
        body=b"",
    )
    sig_hex = sign_payload(priv_bytes, canonical).hex()

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": request_id,
        "X-NETRA-Signature": sig_hex,
    }

    test_client = TestClient(app)
    with test_client.websocket_connect("/api/v1/agent/connect", headers=headers) as websocket:
        data = websocket.receive_json()
        assert data["type"] == "connected"
        assert data["device_id"] == device_id

        # Send ping heartbeat
        websocket.send_json({"type": "ping"})
        pong = websocket.receive_json()
        assert pong["type"] == "pong"


@pytest.mark.asyncio
async def test_wss_handshake_invalid_signature_rejected(client: AsyncClient, app) -> None:
    """Verify WSS handshake with invalid Ed25519 signature is rejected."""
    session_factory = get_session_factory()
    _, pub_bytes = generate_ed25519_keypair()
    pub_hex = pub_bytes.hex()

    async with session_factory() as db:
        tenant = Tenant(name="WSS Invalid Sig Tenant", slug="wss-inv-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="wss-host-inv",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.flush()

        credential = DeviceCredential(
            device_id=device.id,
            public_key=pub_hex,
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(credential)
        await db.commit()

        device_id = device.id

    timestamp_str = str(time.time())
    nonce = str(uuid.uuid4())
    request_id = f"req_{uuid.uuid4().hex[:16]}"
    invalid_sig_hex = "00" * 64

    headers = {
        "X-NETRA-Device-ID": device_id,
        "X-NETRA-Timestamp": timestamp_str,
        "X-NETRA-Nonce": nonce,
        "X-NETRA-Request-ID": request_id,
        "X-NETRA-Signature": invalid_sig_hex,
    }

    test_client = TestClient(app)
    with (
        pytest.raises(WebSocketDisconnect),
        test_client.websocket_connect("/api/v1/agent/connect", headers=headers),
    ):
        pass
