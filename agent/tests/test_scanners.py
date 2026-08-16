"""Unit tests for NETRA host agent capability scanners and scanner registry."""

import os
import tempfile
from pathlib import Path

import pytest
from netra_shared.schemas.task import CapabilityEnum, TaskStatusEnum

from netra_agent.executor import execute_task
from netra_agent.scanners import (
    ConnectionsScanner,
    FileIntegrityScanner,
    FirewallScanner,
    NetworkScanner,
    ProcessScanner,
    ScannerRegistry,
    StartupScanner,
    UsersScanner,
    global_registry,
)


def test_global_registry_contains_all_capabilities() -> None:
    """Verify all 7 CapabilityEnum capabilities are registered in global_registry."""
    for cap in CapabilityEnum:
        assert global_registry.is_registered(cap), f"Capability {cap.value} not registered!"


def test_registry_duplicate_registration_rejected() -> None:
    """Verify registering duplicate scanner for same capability raises ValueError."""
    reg = ScannerRegistry()
    net1 = NetworkScanner()
    net2 = NetworkScanner()
    reg.register(net1)
    with pytest.raises(ValueError, match="already registered"):
        reg.register(net2)


def test_network_scanner_execution() -> None:
    """Verify NetworkScanner returns structured findings."""
    scanner = NetworkScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits({}, "t-1", "e-1")
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1
    assert any(f.category == "NETWORK_INVENTORY" for f in findings)


def test_process_scanner_execution() -> None:
    """Verify ProcessScanner inspects active host processes."""
    scanner = ProcessScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits(
        {"max_processes": 50}, "t-2", "e-2"
    )
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1
    assert any(f.category == "PROCESS_INVENTORY" for f in findings)


def test_connections_scanner_execution() -> None:
    """Verify ConnectionsScanner inspects host sockets."""
    scanner = ConnectionsScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits({}, "t-3", "e-3")
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1
    assert any(f.category == "NETWORK_PORT_INVENTORY" for f in findings)


def test_firewall_scanner_execution() -> None:
    """Verify FirewallScanner checks system firewall status."""
    scanner = FirewallScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits({}, "t-4", "e-4")
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1


def test_users_scanner_execution() -> None:
    """Verify UsersScanner inspects user account metadata without credential leakage."""
    scanner = UsersScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits({}, "t-5", "e-5")
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1
    # Verify passwords or secret fields are NOT in details
    for f in findings:
        details_str = str(f.details).lower()
        assert "password" not in details_str
        assert "hash" not in details_str


def test_startup_scanner_execution() -> None:
    """Verify StartupScanner inspects startup locations."""
    scanner = StartupScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits({}, "t-6", "e-6")
    assert status == TaskStatusEnum.COMPLETED
    assert err is None
    assert len(findings) >= 1


def test_file_integrity_scanner_execution() -> None:
    """Verify FileIntegrityScanner computes SHA-256 hashes for target file."""
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write("NETRA File Integrity Test Payload")
        tmp_path = tmp.name

    try:
        scanner = FileIntegrityScanner()
        status, findings, err, duration = scanner.execute_with_safety_limits(
            {"paths": [tmp_path]}, "t-7", "e-7"
        )
        assert status == TaskStatusEnum.COMPLETED
        assert err is None
        summary_finding = [f for f in findings if f.category == "FILE_INTEGRITY_SUMMARY"][0]
        hashed_files = summary_finding.details["files"]
        assert len(hashed_files) == 1
        assert Path(hashed_files[0]["path"]).resolve() == Path(tmp_path).resolve()
        assert len(hashed_files[0]["sha256"]) == 64
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_task_executor_unknown_capability_rejection() -> None:
    """Verify execute_task fails safely when given unknown capability."""
    res = execute_task("t-99", "e-99", "UNKNOWN_CAP", {})
    assert res["status"] == TaskStatusEnum.FAILED
    assert "Unsupported or unregistered capability" in res["error_message"]
