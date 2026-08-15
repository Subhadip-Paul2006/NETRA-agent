"""NETRA Domain Enums."""

from enum import Enum


class Role(str, Enum):
    """Tenant user role permissions."""

    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    AUDITOR = "AUDITOR"


class TaskStatus(str, Enum):
    """Security assessment task execution status lifecycle."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    DELIVERED = "DELIVERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    """Vulnerability finding lifecycle status."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    MUTED = "MUTED"


class DeviceCredentialStatus(str, Enum):
    """Ed25519 device credential status."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
