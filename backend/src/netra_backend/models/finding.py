"""SQLAlchemy 2.x Finding and FindingEvidence Models for NETRA."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra_backend.models.base import Base
from netra_backend.models.identity import generate_uuid
from netra_shared.enums import FindingStatus, Severity


class Finding(Base):
    """Normalized vulnerability definition master entity model."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "fingerprint", name="uq_tenant_finding_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    execution_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    capability: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, index=True)
    status: Mapped[FindingStatus] = mapped_column(
        SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC), nullable=False
    )

    evidences: Mapped[list["FindingEvidence"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="FindingEvidence.observed_at.desc()",
    )


class FindingEvidence(Base):
    """Specific scan observation evidence entity model."""

    __tablename__ = "finding_evidences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("task_executions.execution_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="evidences")
