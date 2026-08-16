"""Unit tests for shared task schemas and enums."""

import pytest
from pydantic import ValidationError

from netra_shared.schemas import (
    CapabilityEnum,
    TaskCreateRequest,
    TaskPriorityEnum,
    TaskStatusEnum,
)


def test_capability_enum_validation() -> None:
    """Verify registered capabilities are accepted and unknown strings rejected."""
    assert CapabilityEnum.SCAN_NETWORK == "SCAN_NETWORK"
    assert CapabilityEnum.SCAN_PROCESSES == "SCAN_PROCESSES"

    valid_req = TaskCreateRequest(
        target_device_id="dev-123",
        capability=CapabilityEnum.SCAN_NETWORK,
        priority=TaskPriorityEnum.HIGH,
    )
    assert valid_req.capability == CapabilityEnum.SCAN_NETWORK

    with pytest.raises(ValidationError):
        TaskCreateRequest(
            target_device_id="dev-123",
            capability="RM_RF_SLASH",  # Arbitrary command string rejected!  # type: ignore[arg-type]
        )


def test_task_status_enum_values() -> None:
    """Verify TaskStatusEnum contains all required Phase 5 lifecycle states."""
    expected_states = {
        "CREATED",
        "QUEUED",
        "DELIVERED",
        "ACKNOWLEDGED",
        "RUNNING",
        "COMPLETED",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
        "TIMEOUT",
    }
    actual_states = {status.value for status in TaskStatusEnum}
    assert expected_states == actual_states
