"""NETRA Pydantic v2 Domain Schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from netra_shared.enums import Role, TaskStatus


class ErrorEnvelopeSchema(BaseModel):
    """Standard error response envelope."""

    model_config = ConfigDict(frozen=True)

    success: bool = False
    error: dict[str, Any]


class TenantSchema(BaseModel):
    """Tenant organization domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    created_at: datetime
    updated_at: datetime


class UserSchema(BaseModel):
    """User identity domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TenantMembershipSchema(BaseModel):
    """User tenant membership domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: str
    role: Role
    created_at: datetime


class DeviceSchema(BaseModel):
    """Host device domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    hostname: str
    os: str
    architecture: str
    agent_version: str
    is_paired: bool
    last_heartbeat_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class TaskSchema(BaseModel):
    """Task domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    device_id: str
    capability: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: TaskStatus
    created_at: datetime
    updated_at: datetime


from netra_shared.schemas.finding import (
    FindingDetailSchema,
    FindingEvidenceSchema,
    FindingPaginatedResponse,
    FindingSchema,
    FindingStatusUpdateRequest,
)
from netra_shared.schemas.task import (
    CapabilityEnum,
    FindingItem,
    TaskAckRequest,
    TaskCancelResponse,
    TaskCreateRequest,
    TaskPriorityEnum,
    TaskResponse,
    TaskResultRequest,
    TaskStartRequest,
    TaskStatusEnum,
)

__all__ = [
    "CapabilityEnum",
    "DeviceSchema",
    "ErrorEnvelopeSchema",
    "FindingDetailSchema",
    "FindingEvidenceSchema",
    "FindingItem",
    "FindingPaginatedResponse",
    "FindingSchema",
    "FindingStatusUpdateRequest",
    "TaskAckRequest",
    "TaskCancelResponse",
    "TaskCreateRequest",
    "TaskPriorityEnum",
    "TaskResponse",
    "TaskResultRequest",
    "TaskSchema",
    "TaskStartRequest",
    "TaskStatusEnum",
    "TenantMembershipSchema",
    "TenantSchema",
    "UserSchema",
]
