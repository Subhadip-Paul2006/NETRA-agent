"""Shared Pydantic v2 Schemas for Security Findings & Evidence Intelligence."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from netra_shared.enums import FindingStatus, Severity


class FindingEvidenceSchema(BaseModel):
    """Schema for scan observation evidence item."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    finding_id: str
    device_id: str
    task_id: str
    execution_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime


class FindingSchema(BaseModel):
    """Vulnerability finding domain schema."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    device_id: str | None = None
    task_id: str | None = None
    execution_id: str | None = None
    capability: str | None = None
    title: str
    description: str | None = None
    category: str
    severity: Severity
    status: FindingStatus
    fingerprint: str
    remediation: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FindingDetailSchema(FindingSchema):
    """Detailed finding schema including attached evidence history."""

    evidences: list[FindingEvidenceSchema] = Field(default_factory=list)


class FindingStatusUpdateRequest(BaseModel):
    """Payload for updating finding lifecycle status."""

    status: FindingStatus


class FindingPaginatedResponse(BaseModel):
    """Paginated findings listing response envelope."""

    items: list[FindingSchema]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    has_more: bool
