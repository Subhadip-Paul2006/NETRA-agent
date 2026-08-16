"""Integration tests for Phase 5 Task Orchestration Lifecycle API endpoints."""

import json
import time
import uuid

import pytest
from httpx import AsyncClient

from netra_backend.database import get_session_factory
from netra_backend.models import (
    Device,
    DeviceCredential,
    Tenant,
    TenantMembership,
    User,
)
from netra_backend.security import create_access_token, hash_password
from netra_shared.crypto import construct_canonical_payload, generate_ed25519_keypair, sign_payload
from netra_shared.enums import DeviceCredentialStatus, Role


@pytest.mark.asyncio
async def test_full_task_orchestration_lifecycle_flow(client: AsyncClient, app) -> None:
    """End-to-end integration test:

    1. Admin creates task via POST /api/v1/control/tasks
    2. Agent polls tasks via GET /api/v1/agent/tasks (Claims task)
    3. Agent ACK task via POST /api/v1/agent/tasks/{id}/ack
    4. Agent starts task via POST /api/v1/agent/tasks/{id}/start
    5. Agent submits results via POST /api/v1/agent/tasks/{id}/results
    """
    session_factory = get_session_factory()
    password = "AdminPassword123!"
    priv_bytes, pub_bytes = generate_ed25519_keypair()

    async with session_factory() as db:
        tenant = Tenant(name="Lifecycle Tenant", slug="lifecycle-tenant")
        admin_user = User(
            email="admin@lifecycle.io",
            password_hash=hash_password(password),
            display_name="Admin User",
            is_active=True,
        )
        db.add(tenant)
        db.add(admin_user)
        await db.flush()

        membership = TenantMembership(tenant_id=tenant.id, user_id=admin_user.id, role=Role.ADMIN)
        db.add(membership)

        device = Device(
            tenant_id=tenant.id,
            hostname="target-host",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.flush()

        credential = DeviceCredential(
            device_id=device.id,
            public_key=pub_bytes.hex(),
            algorithm="Ed25519",
            status=DeviceCredentialStatus.ACTIVE,
        )
        db.add(credential)
        await db.commit()

        tenant_id = tenant.id
        user_id = admin_user.id
        device_id = device.id

    # 1. User creates task
    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    auth_headers = {"Authorization": f"Bearer {token}"}

    create_res = await client.post(
        "/api/v1/control/tasks",
        json={
            "target_device_id": device_id,
            "capability": "SCAN_NETWORK",
            "parameters": {"target": "10.0.0.0/24"},
            "priority": "HIGH",
        },
        headers=auth_headers,
    )
    assert create_res.status_code == 200
    task_data = create_res.json()
    task_id = task_data["id"]
    assert task_data["status"] == "QUEUED"

    # Helper function for signing agent requests
    def build_agent_headers(method: str, path: str, body_bytes: bytes) -> dict[str, str]:
        timestamp_str = str(time.time())
        nonce = str(uuid.uuid4())
        request_id = f"req_{uuid.uuid4().hex[:16]}"
        canonical = construct_canonical_payload(
            method=method,
            path=path,
            timestamp=timestamp_str,
            nonce=nonce,
            request_id=request_id,
            body=body_bytes,
        )
        sig_hex = sign_payload(priv_bytes, canonical).hex()
        return {
            "X-NETRA-Device-ID": device_id,
            "X-NETRA-Timestamp": timestamp_str,
            "X-NETRA-Nonce": nonce,
            "X-NETRA-Request-ID": request_id,
            "X-NETRA-Signature": sig_hex,
        }

    # 2. Agent polls and claims task
    poll_headers = build_agent_headers("GET", "/api/v1/agent/tasks", b"")
    poll_res = await client.get("/api/v1/agent/tasks", headers=poll_headers)
    assert poll_res.status_code == 200
    claimed_tasks = poll_res.json()["tasks"]
    assert len(claimed_tasks) == 1
    claimed_item = claimed_tasks[0]
    assert claimed_item["id"] == task_id
    execution_id = claimed_item["execution_id"]

    # 3. Agent ACK
    ack_path = f"/api/v1/agent/tasks/{task_id}/ack"
    ack_body = {"task_id": task_id, "execution_id": execution_id}
    ack_bytes = json.dumps(ack_body).encode("utf-8")
    ack_headers = build_agent_headers("POST", ack_path, ack_bytes)
    ack_headers["Content-Type"] = "application/json"
    ack_res = await client.post(ack_path, content=ack_bytes, headers=ack_headers)
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    # 4. Agent Start
    start_path = f"/api/v1/agent/tasks/{task_id}/start"
    start_body = {"task_id": task_id, "execution_id": execution_id}
    start_bytes = json.dumps(start_body).encode("utf-8")
    start_headers = build_agent_headers("POST", start_path, start_bytes)
    start_headers["Content-Type"] = "application/json"
    start_res = await client.post(start_path, content=start_bytes, headers=start_headers)
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "RUNNING"

    # 5. Agent Submit Result (Completed with findings)
    result_path = f"/api/v1/agent/tasks/{task_id}/results"
    result_body = {
        "task_id": task_id,
        "execution_id": execution_id,
        "status": "COMPLETED",
        "execution_time_ms": 150,
        "findings": [
            {
                "title": "Open Port 22 SSH",
                "category": "NETWORK_SERVICE",
                "severity": "MEDIUM",
                "fingerprint": "fp_ssh_22",
                "details": {"port": 22, "service": "OpenSSH"},
            }
        ],
    }
    result_bytes = json.dumps(result_body).encode("utf-8")
    result_headers = build_agent_headers("POST", result_path, result_bytes)
    result_headers["Content-Type"] = "application/json"
    result_res = await client.post(result_path, content=result_bytes, headers=result_headers)
    assert result_res.status_code == 200
    assert result_res.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_task_cancellation_flow(client: AsyncClient, app) -> None:
    """Verify user can cancel a queued task."""
    session_factory = get_session_factory()
    password = "CancelPassword123!"

    async with session_factory() as db:
        tenant = Tenant(name="Cancel Tenant", slug="cancel-tenant")
        admin_user = User(
            email="admin@cancel.io",
            password_hash=hash_password(password),
            display_name="Admin User",
            is_active=True,
        )
        db.add(tenant)
        db.add(admin_user)
        await db.flush()

        membership = TenantMembership(tenant_id=tenant.id, user_id=admin_user.id, role=Role.ADMIN)
        db.add(membership)

        device = Device(
            tenant_id=tenant.id,
            hostname="cancel-host",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1.0",
            is_paired=True,
        )
        db.add(device)
        await db.commit()

        tenant_id = tenant.id
        user_id = admin_user.id
        device_id = device.id

    token = create_access_token(user_id=user_id, tenant_id=tenant_id)
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Create task
    create_res = await client.post(
        "/api/v1/control/tasks",
        json={
            "target_device_id": device_id,
            "capability": "SCAN_PROCESSES",
            "priority": "LOW",
        },
        headers=auth_headers,
    )
    task_id = create_res.json()["id"]

    # Cancel task
    cancel_res = await client.post(
        f"/api/v1/control/tasks/{task_id}/cancel",
        headers=auth_headers,
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"
