"""SQLAlchemy 2.x Host Device and Credential Models."""

from datetime import UTC, datetime

from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netra_backend.models.base import Base
from netra_backend.models.identity import generate_uuid
from netra_shared.enums import DeviceCredentialStatus


class Device(Base):
    """Host device entity model."""

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os: Mapped[str] = mapped_column(String(50), nullable=False)
    architecture: Mapped[str] = mapped_column(String(50), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(20), nullable=False)
    is_paired: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    credential: Mapped["DeviceCredential | None"] = relationship(
        back_populates="device", uselist=False, cascade="all, delete-orphan"
    )
    agent_sessions: Mapped[list["AgentSession"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceCredential(Base):
    """Ed25519 Device Credential entity model.

    NOTE: Stores only the device public key. Private keys are NEVER stored in the backend database.
    """

    __tablename__ = "device_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    public_key: Mapped[str] = mapped_column(String(512), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(50), default="Ed25519", nullable=False)
    status: Mapped[DeviceCredentialStatus] = mapped_column(
        SQLEnum(DeviceCredentialStatus), default=DeviceCredentialStatus.ACTIVE, nullable=False
    )
    rotation_count: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
    last_rotated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)

    device: Mapped["Device"] = relationship(back_populates="credential")


class AgentSession(Base):
    """Active Agent WebSocket / REST connection session entity model."""

    __tablename__ = "agent_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connection_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    connected_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), nullable=False
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)

    device: Mapped["Device"] = relationship(back_populates="agent_sessions")
