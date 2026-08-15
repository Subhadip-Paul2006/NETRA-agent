"""SQLAlchemy 2.x Task and Execution Models."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra_backend.models.base import Base
from netra_backend.models.identity import generate_uuid
from netra_shared.enums import TaskStatus


class Task(Base):
    """Security assessment task entity model."""

    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    capability: Mapped[str] = mapped_column(String(100), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        SQLEnum(TaskStatus), default=TaskStatus.CREATED, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    executions: Mapped[list["TaskExecution"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class TaskExecution(Base):
    """Task execution attempt entity model."""

    __tablename__ = "task_executions"
    __table_args__ = (UniqueConstraint("task_id", "execution_id", name="uq_task_execution"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[TaskStatus] = mapped_column(SQLEnum(TaskStatus), nullable=False)
    started_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    task: Mapped["Task"] = relationship(back_populates="executions")
