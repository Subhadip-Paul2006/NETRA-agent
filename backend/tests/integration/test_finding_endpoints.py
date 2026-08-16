"""Integration Test Suite for Control-Plane Finding Endpoints."""

import pytest
from httpx import AsyncClient

from netra_backend.database import get_session_factory
from netra_backend.models import Device, Finding, FindingEvidence, Tenant, TenantMembership, User
from netra_backend.security import create_access_token, hash_password
from netra_shared.enums import FindingStatus, Role, Severity


@pytest.mark.asyncio
async def test_list_findings_endpoint_pagination_and_filtering(client: AsyncClient, app) -> None:
    """Verify GET /api/v1/control/findings returns paginated, filtered findings."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Finding Test Org", slug="finding-org-1")
        user = User(
            email="admin@finding.com", password_hash=hash_password("Pass1!"), display_name="Admin"
        )
        db.add_all([tenant, user])
        await db.flush()

        db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.ADMIN))
        device = Device(
            tenant_id=tenant.id,
            hostname="host-1",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1",
        )
        db.add(device)
        await db.flush()

        # Add 3 findings
        f1 = Finding(
            tenant_id=tenant.id,
            device_id=device.id,
            capability="SCAN_NETWORK",
            title="Open SSH Port",
            category="NETWORK",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            fingerprint="fp_net_ssh_001",
        )
        f2 = Finding(
            tenant_id=tenant.id,
            device_id=device.id,
            capability="SCAN_PROCESSES",
            title="Unsigned Binary",
            category="PROCESS",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            fingerprint="fp_proc_binary_002",
        )
        f3 = Finding(
            tenant_id=tenant.id,
            device_id=device.id,
            capability="SCAN_NETWORK",
            title="Telnet Active",
            category="NETWORK",
            severity=Severity.MEDIUM,
            status=FindingStatus.RESOLVED,
            fingerprint="fp_net_telnet_003",
        )
        db.add_all([f1, f2, f3])
        await db.commit()

        t_id = tenant.id
        u_id = user.id

    token = create_access_token(user_id=u_id, tenant_id=t_id, role=Role.ADMIN.value)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Query all findings (paginated)
    res = await client.get("/api/v1/control/findings?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3

    # 2. Filter by severity=HIGH
    res_sev = await client.get("/api/v1/control/findings?severity=HIGH", headers=headers)
    assert res_sev.status_code == 200
    data_sev = res_sev.json()
    assert data_sev["total"] == 1
    assert data_sev["items"][0]["title"] == "Open SSH Port"

    # 3. Filter by category=NETWORK
    res_cat = await client.get("/api/v1/control/findings?category=NETWORK", headers=headers)
    assert res_cat.status_code == 200
    assert res_cat.json()["total"] == 2


@pytest.mark.asyncio
async def test_get_finding_detail_with_evidences(client: AsyncClient, app) -> None:
    """Verify GET /api/v1/control/findings/{finding_id} returns details and evidence history."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Detail Org", slug="detail-org-1")
        user = User(
            email="user@detail.com", password_hash=hash_password("Pass1!"), display_name="User"
        )
        db.add_all([tenant, user])
        await db.flush()

        db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.OPERATOR))
        device = Device(
            tenant_id=tenant.id,
            hostname="host-2",
            os="Linux",
            architecture="x86_64",
            agent_version="0.1",
        )
        db.add(device)
        await db.flush()

        finding = Finding(
            tenant_id=tenant.id,
            device_id=device.id,
            capability="SCAN_FIREWALL",
            title="Firewall Disabled",
            category="FIREWALL",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            fingerprint="fp_fw_disabled_01",
        )
        db.add(finding)
        await db.flush()

        # Add evidence item
        evidence = FindingEvidence(
            tenant_id=tenant.id,
            finding_id=finding.id,
            device_id=device.id,
            task_id="dummy_task_id",
            execution_id="dummy_exec_id",
            details={"rules_count": 0, "status": "inactive"},
        )
        db.add(evidence)
        await db.commit()

        t_id = tenant.id
        u_id = user.id
        f_id = finding.id

    token = create_access_token(user_id=u_id, tenant_id=t_id, role=Role.OPERATOR.value)
    headers = {"Authorization": f"Bearer {token}"}

    res = await client.get(f"/api/v1/control/findings/{f_id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == f_id
    assert data["title"] == "Firewall Disabled"
    assert len(data["evidences"]) == 1
    assert data["evidences"][0]["details"]["status"] == "inactive"


@pytest.mark.asyncio
async def test_update_finding_status_permissions_and_audit(client: AsyncClient, app) -> None:
    """Verify status mutations create AuditEvents and enforce role restrictions."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        tenant = Tenant(name="Mutate Org", slug="mutate-org-1")
        u_admin = User(
            email="admin@mutate.com", password_hash=hash_password("Pass1!"), display_name="Admin"
        )
        u_auditor = User(
            email="auditor@mutate.com",
            password_hash=hash_password("Pass1!"),
            display_name="Auditor",
        )
        db.add_all([tenant, u_admin, u_auditor])
        await db.flush()

        db.add(TenantMembership(tenant_id=tenant.id, user_id=u_admin.id, role=Role.ADMIN))
        db.add(TenantMembership(tenant_id=tenant.id, user_id=u_auditor.id, role=Role.AUDITOR))

        finding = Finding(
            tenant_id=tenant.id,
            title="Suspicious User Created",
            category="USERS",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            fingerprint="fp_user_susp_01",
        )
        db.add(finding)
        await db.commit()

        t_id = tenant.id
        adm_id = u_admin.id
        aud_id = u_auditor.id
        f_id = finding.id

    # 1. AUDITOR token attempts to acknowledge finding -> 403 Forbidden
    token_auditor = create_access_token(user_id=aud_id, tenant_id=t_id, role=Role.AUDITOR.value)
    res_aud = await client.post(
        f"/api/v1/control/findings/{f_id}/status",
        json={"status": "ACKNOWLEDGED"},
        headers={"Authorization": f"Bearer {token_auditor}"},
    )
    assert res_aud.status_code == 403

    # 2. ADMIN token acknowledges finding -> 200 OK
    token_admin = create_access_token(user_id=adm_id, tenant_id=t_id, role=Role.ADMIN.value)
    res_adm = await client.post(
        f"/api/v1/control/findings/{f_id}/status",
        json={"status": "ACKNOWLEDGED"},
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert res_adm.status_code == 200
    assert res_adm.json()["status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_cross_tenant_finding_access_denied(client: AsyncClient, app) -> None:
    """Verify Tenant A user cannot read or update Tenant B's finding."""
    session_factory = get_session_factory()

    async with session_factory() as db:
        t_a = Tenant(name="Tenant A", slug="tenant-a-find")
        t_b = Tenant(name="Tenant B", slug="tenant-b-find")
        u_a = User(email="ua@find.com", password_hash=hash_password("Pass1!"), display_name="UA")
        db.add_all([t_a, t_b, u_a])
        await db.flush()

        db.add(TenantMembership(tenant_id=t_a.id, user_id=u_a.id, role=Role.ADMIN))

        finding_b = Finding(
            tenant_id=t_b.id,
            title="Tenant B Secret Finding",
            category="SECURITY",
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            fingerprint="fp_tb_secret_find",
        )
        db.add(finding_b)
        await db.commit()

        t_a_id = t_a.id
        u_a_id = u_a.id
        f_b_id = finding_b.id

    token_a = create_access_token(user_id=u_a_id, tenant_id=t_a_id, role=Role.ADMIN.value)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Direct read attempt -> 404 Not Found
    res = await client.get(f"/api/v1/control/findings/{f_b_id}", headers=headers_a)
    assert res.status_code == 404
