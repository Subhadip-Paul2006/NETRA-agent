"""Unit tests for pure SQLAlchemy 2.x Entity Models."""

from netra_backend.models import (
    Base,
    Device,
    DeviceCredential,
    Finding,
    Tenant,
    TenantMembership,
    User,
)
from netra_shared.enums import FindingStatus, Role, Severity


def test_base_metadata_contains_all_models() -> None:
    """Verify single DeclarativeBase metadata source contains all 16 registered tables."""
    tables = Base.metadata.tables.keys()

    expected_tables = {
        "tenants",
        "users",
        "tenant_memberships",
        "user_sessions",
        "devices",
        "device_credentials",
        "agent_sessions",
        "tasks",
        "task_executions",
        "findings",
        "finding_evidences",
        "discord_bindings",
        "discord_sessions",
        "audit_events",
        "enrollment_codes",
        "nonce_caches",
    }

    assert expected_tables.issubset(set(tables))


def test_model_instantiation() -> None:
    """Verify model instances set expected defaults and attributes."""
    tenant = Tenant(name="Acme Security", slug="acme-sec")
    user = User(email="admin@acme.com", password_hash="hashed", display_name="Admin")
    membership = TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.ADMIN)

    device = Device(
        tenant_id=tenant.id,
        hostname="workstation-01",
        os="Windows 11",
        architecture="x86_64",
        agent_version="1.0.0",
    )
    cred = DeviceCredential(
        device_id=device.id, public_key="ed25519_pub_key_hex", algorithm="Ed25519"
    )

    finding = Finding(
        tenant_id=tenant.id,
        title="Open Port 22 SSH",
        category="NETWORK",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        fingerprint="sha256_fingerprint_hex",
    )

    assert tenant.slug == "acme-sec"
    assert user.display_name == "Admin"
    assert membership.role == Role.ADMIN
    assert device.hostname == "workstation-01"
    assert cred.algorithm == "Ed25519"
    assert finding.severity == Severity.HIGH
