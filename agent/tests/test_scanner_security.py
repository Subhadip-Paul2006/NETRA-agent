"""Security and Safety Boundary Tests for NETRA Host Agent Scanners."""

from netra_shared.schemas.task import TaskStatusEnum

from netra_agent.scanners import FileIntegrityScanner, NetworkScanner, ProcessScanner


def test_network_scanner_shell_injection_rejection() -> None:
    """Verify NetworkScanner rejects parameter keys containing shell injection payloads."""
    scanner = NetworkScanner()
    malicious_params = {"target; rm -rf /": "value"}
    status, findings, err, duration = scanner.execute_with_safety_limits(
        malicious_params, "t-sec-1", "e-sec-1"
    )
    assert status == TaskStatusEnum.FAILED
    assert "Illegal character" in str(err)


def test_process_scanner_invalid_max_processes_rejection() -> None:
    """Verify ProcessScanner rejects negative or excessive max_processes counts."""
    scanner = ProcessScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits(
        {"max_processes": -10}, "t-sec-2", "e-sec-2"
    )
    assert status == TaskStatusEnum.FAILED
    assert "max_processes must be an integer" in str(err)


def test_file_integrity_shell_injection_rejection() -> None:
    """Verify FileIntegrityScanner rejects paths with shell operators or pipe characters."""
    scanner = FileIntegrityScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits(
        {"paths": ["/etc/passwd; cat /etc/shadow"]}, "t-sec-3", "e-sec-3"
    )
    assert status == TaskStatusEnum.FAILED
    assert "Illegal character" in str(err)


def test_file_integrity_virtual_filesystem_rejection() -> None:
    """Verify FileIntegrityScanner rejects target paths pointing to /proc, /sys, /dev."""
    scanner = FileIntegrityScanner()
    status, findings, err, duration = scanner.execute_with_safety_limits(
        {"paths": ["/proc/1/mem"]}, "t-sec-4", "e-sec-4"
    )
    assert status == TaskStatusEnum.FAILED
    assert "forbidden system virtual filesystem" in str(err)


def test_file_integrity_max_file_count_limit_rejection() -> None:
    """Verify FileIntegrityScanner rejects scanning more than 50 files in a single task."""
    scanner = FileIntegrityScanner()
    excessive_paths = [f"/tmp/test_file_{i}.txt" for i in range(55)]
    status, findings, err, duration = scanner.execute_with_safety_limits(
        {"paths": excessive_paths}, "t-sec-5", "e-sec-5"
    )
    assert status == TaskStatusEnum.FAILED
    assert "Exceeded maximum file scan limit" in str(err)
