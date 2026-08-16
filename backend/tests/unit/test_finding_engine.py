"""Unit Test Suite for Finding Engine, Fingerprinting, and State Transitions."""

import pytest
from fastapi import HTTPException

from netra_backend.services.finding_engine import (
    MAX_EVIDENCE_SIZE_BYTES,
    compute_finding_fingerprint,
    validate_finding_transition,
)
from netra_shared.enums import FindingStatus


def test_deterministic_finding_fingerprint() -> None:
    """Verify SHA-256 finding fingerprint is deterministic across identical inputs."""
    fp1 = compute_finding_fingerprint(
        tenant_id="tenant-123",
        device_id="device-456",
        capability="SCAN_NETWORK",
        category="NETWORK",
        title="Open Port 22 Found",
        resource_key="port:22",
    )
    fp2 = compute_finding_fingerprint(
        tenant_id="tenant-123",
        device_id="device-456",
        capability="SCAN_NETWORK",
        category="NETWORK",
        title="Open Port 22 Found",
        resource_key="port:22",
    )
    assert len(fp1) == 64
    assert fp1 == fp2


def test_fingerprint_changes_on_different_tenant_or_device() -> None:
    """Verify fingerprint differs when tenant or resource changes."""
    fp1 = compute_finding_fingerprint(
        tenant_id="tenant-A",
        device_id="device-1",
        capability="SCAN_NETWORK",
        category="NETWORK",
        title="Vulnerability X",
    )
    fp2 = compute_finding_fingerprint(
        tenant_id="tenant-B",
        device_id="device-1",
        capability="SCAN_NETWORK",
        category="NETWORK",
        title="Vulnerability X",
    )
    assert fp1 != fp2


def test_valid_finding_status_transitions() -> None:
    """Verify valid finding status lifecycle transitions succeed."""
    # OPEN -> ACKNOWLEDGED / RESOLVED
    validate_finding_transition(FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)
    validate_finding_transition(FindingStatus.OPEN, FindingStatus.RESOLVED)

    # ACKNOWLEDGED -> RESOLVED / OPEN
    validate_finding_transition(FindingStatus.ACKNOWLEDGED, FindingStatus.RESOLVED)
    validate_finding_transition(FindingStatus.ACKNOWLEDGED, FindingStatus.OPEN)

    # RESOLVED -> REOPENED
    validate_finding_transition(FindingStatus.RESOLVED, FindingStatus.REOPENED)

    # REOPENED -> ACKNOWLEDGED / RESOLVED
    validate_finding_transition(FindingStatus.REOPENED, FindingStatus.ACKNOWLEDGED)
    validate_finding_transition(FindingStatus.REOPENED, FindingStatus.RESOLVED)


def test_invalid_finding_status_transition_raises_http_exception() -> None:
    """Verify invalid finding transitions raise 400 Bad Request."""
    with pytest.raises(HTTPException) as exc_info:
        validate_finding_transition(FindingStatus.RESOLVED, FindingStatus.ACKNOWLEDGED)
    assert exc_info.value.status_code == 400
    assert "Invalid finding status transition" in exc_info.value.detail


def test_max_evidence_size_constant() -> None:
    """Verify evidence size limit safety constant."""
    assert MAX_EVIDENCE_SIZE_BYTES == 1024 * 1024
