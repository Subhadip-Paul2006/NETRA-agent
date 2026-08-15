"""Integration tests for agent REST polling fallback endpoint."""

import time
import uuid

import pytest
from httpx import AsyncClient

from netra_backend.database import get_session_factory
from netra_backend.models import Device, DeviceCredential, Tenant
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus


@pytest.mark.asyncio
async def test_poll_agent_tasks_success(client: AsyncClient, app) -> None:
    """Verify agent can poll pending tasks using valid Ed25519 security headers."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    pub_hex = pub_bytes.hex()

    async with session_factory() as db:
        tenant = Tenant(name="Poll Tenant", slug="poll-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="poll-host-01",
            os="Windows",
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
        path="/api/v1/agent/tasks",
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

    res = await client.get("/api/v1/agent/tasks", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["tasks"] == []


@pytest.mark.asyncio
async def test_poll_agent_tasks_replay_nonce_rejected(client: AsyncClient, app) -> None:
    """Verify duplicate nonce replay attempt is rejected with HTTP 400."""
    session_factory = get_session_factory()
    priv_bytes, pub_bytes = generate_ed25519_keypair()
    pub_hex = pub_bytes.hex()

    async with session_factory() as db:
        tenant = Tenant(name="Poll Replay Tenant", slug="poll-replay-tenant")
        db.add(tenant)
        await db.flush()

        device = Device(
            tenant_id=tenant.id,
            hostname="poll-host-replay",
            os="Windows",
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
        path="/api/v1/agent/tasks",
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

    # First request -> Success
    res1 = await client.get("/api/v1/agent/tasks", headers=headers)
    assert res1.status_code == 200

    # Second request with SAME nonce -> 400 Bad Request Replay Rejection
    res2 = await client.get("/api/v1/agent/tasks", headers=headers)
    assert res2.status_code == 400
    assert "Replay attack detected" in res2.json()["error"]["message"]
