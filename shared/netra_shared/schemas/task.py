"""Shared Pydantic Schemas and Enums for NETRA Task Orchestration."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CapabilityEnum(str, Enum):
    """Controlled capability model registry. Arbitrary shell strings prohibited."""

    SCAN_NETWORK = "SCAN_NETWORK"
    SCAN_PROCESSES = "SCAN_PROCESSES"
    SCAN_CONNECTIONS = "SCAN_CONNECTIONS"
    SCAN_FIREWALL = "SCAN_FIREWALL"
    SCAN_USERS = "SCAN_USERS"
    SCAN_STARTUP = "SCAN_STARTUP"
    SCAN_FILE_INTEGRITY = "SCAN_FILE_INTEGRITY"


class TaskPriorityEnum(str, Enum):
    """Task priority level enum."""

    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"


from netra_shared.enums import TaskStatus

TaskStatusEnum = TaskStatus


class TaskCreateRequest(BaseModel):
    """Payload for creating a new security task."""

    target_device_id: str = Field(..., min_length=1)
    capability: CapabilityEnum
    parameters: dict[str, Any] = Field(default_factory=dict)
    priority: TaskPriorityEnum = TaskPriorityEnum.NORMAL


class TaskResponse(BaseModel):
    """Task Entity Response Envelope."""

    id: str
    tenant_id: str
    device_id: str
    capability: CapabilityEnum
    parameters: dict[str, Any]
    status: TaskStatusEnum
    priority: TaskPriorityEnum
    created_at: datetime
    queued_at: datetime | None = None
    delivered_at: datetime | None = None
    acknowledged_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    expires_at: datetime | None = None


class TaskAckRequest(BaseModel):
    """Payload for agent task delivery acknowledgement."""

    task_id: str
    execution_id: str


class TaskStartRequest(BaseModel):
    """Payload for marking task execution started."""

    task_id: str
    execution_id: str


class FindingItem(BaseModel):
    """Finding Evidence Payload Schema."""

    title: str
    category: str
    severity: str
    fingerprint: str
    details: dict[str, Any] = Field(default_factory=dict)


class TaskResultRequest(BaseModel):
    """Payload for submitting task execution results."""

    task_id: str
    execution_id: str
    status: TaskStatusEnum
    execution_time_ms: int = Field(ge=0)
    findings: list[FindingItem] = Field(default_factory=list)
    error_message: str | None = None


class TaskCancelResponse(BaseModel):
    """Task Cancellation Response Envelope."""

    task_id: str
    status: TaskStatusEnum = TaskStatusEnum.CANCELLED
