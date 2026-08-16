"""Capability Scanner Registry for NETRA Host Agent."""

from netra_backend.logging import get_logger
from netra_shared.schemas.task import CapabilityEnum

from netra_agent.scanners.base import BaseScanner

logger = get_logger(__name__)


class ScannerRegistry:
    """Registry mapping CapabilityEnum capabilities to BaseScanner implementations."""

    def __init__(self) -> None:
        self._scanners: dict[CapabilityEnum, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        """Register a scanner instance for its declared capability."""
        cap = scanner.capability
        if cap in self._scanners:
            raise ValueError(f"Scanner for capability '{cap.value}' is already registered.")
        self._scanners[cap] = scanner
        logger.info(
            "scanner_registered",
            capability=cap.value,
            scanner_class=scanner.__class__.__name__,
        )

    def get_scanner(self, capability: str | CapabilityEnum) -> BaseScanner | None:
        """Retrieve scanner instance for given capability string or CapabilityEnum."""
        if isinstance(capability, str):
            try:
                cap_enum = CapabilityEnum(capability)
            except ValueError:
                return None
        else:
            cap_enum = capability

        return self._scanners.get(cap_enum)

    def is_registered(self, capability: str | CapabilityEnum) -> bool:
        """Check if scanner for capability is registered."""
        return self.get_scanner(capability) is not None


# Global agent scanner registry instance
global_registry = ScannerRegistry()
