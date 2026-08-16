"""Unit tests for task engine state machine transition rules."""

import pytest
from fastapi import HTTPException

from netra_backend.services.task_engine import validate_state_transition
from netra_shared.enums import TaskStatus


def test_valid_state_transitions() -> None:
    """Verify valid lifecycle state transitions pass without exception."""
    validate_state_transition(TaskStatus.CREATED, TaskStatus.QUEUED)
    validate_state_transition(TaskStatus.QUEUED, TaskStatus.DELIVERED)
    validate_state_transition(TaskStatus.DELIVERED, TaskStatus.ACKNOWLEDGED)
    validate_state_transition(TaskStatus.ACKNOWLEDGED, TaskStatus.RUNNING)
    validate_state_transition(TaskStatus.RUNNING, TaskStatus.COMPLETED)
    validate_state_transition(TaskStatus.RUNNING, TaskStatus.FAILED)


def test_invalid_state_transitions_raise_http_exception() -> None:
    """Verify invalid state transitions raise HTTP 400 Bad Request."""
    with pytest.raises(HTTPException) as exc_info:
        validate_state_transition(TaskStatus.CREATED, TaskStatus.COMPLETED)
    assert exc_info.value.status_code == 400

    with pytest.raises(HTTPException) as exc_info:
        validate_state_transition(TaskStatus.COMPLETED, TaskStatus.RUNNING)
    assert exc_info.value.status_code == 400

    with pytest.raises(HTTPException) as exc_info:
        validate_state_transition(TaskStatus.CANCELLED, TaskStatus.QUEUED)
    assert exc_info.value.status_code == 400


def test_idempotent_reentry_allowed() -> None:
    """Verify transitioning from state X to state X is allowed as idempotent re-entry."""
    validate_state_transition(TaskStatus.RUNNING, TaskStatus.RUNNING)
    validate_state_transition(TaskStatus.COMPLETED, TaskStatus.COMPLETED)
