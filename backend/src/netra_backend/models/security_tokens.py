"""SQLAlchemy 2.x Enrollment Code and Nonce Cache Models."""

from datetime import UTC, datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from netra_backend.models.base import Base
from netra_backend.models.identity import generate_uuid


class EnrollmentCode(Base):
    """Single-use device enrollment authorization code entity model."""

    __tablename__ = "enrollment_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(nullable=True, default=None)
    used_by_device_id: Mapped[str | None] = mapped_column(String(36), nullable=True, default=None)
    is_revoked: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)


class NonceCache(Base):
    """WSS signature anti-replay nonce cache entity model."""

    __tablename__ = "nonce_caches"
    __table_args__ = (UniqueConstraint("device_id", "nonce", name="uq_device_nonce"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)
