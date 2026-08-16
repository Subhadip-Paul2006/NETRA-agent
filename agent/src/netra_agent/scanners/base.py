"""Base Scanner Interface and Defensive Safety Wrapper for NETRA Host Agent."""

import time
from abc import ABC, abstractmethod
from typing import Any

from netra_backend.logging import get_logger
from netra_shared.schemas.task import CapabilityEnum, FindingItem, TaskStatusEnum

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Abstract Base Class for all defensive NETRA host scanners."""

    @property
    @abstractmethod
    def capability(self) -> CapabilityEnum:
        """Returns the registered CapabilityEnum associated with this scanner."""
        ...

    @abstractmethod
    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Validate input parameters.

        Raises:
            ValueError: If input parameters violate safe boundaries.
        """
        ...

    @abstractmethod
    def run_scan(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> list[FindingItem]:
        """Perform host scan inspection and return list of FindingItem objects.

        MUST NOT execute arbitrary shell commands or collect credentials.
        """
        ...

    def execute_with_safety_limits(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> tuple[TaskStatusEnum, list[FindingItem], str | None, int]:
        """Execute scan safely with exception isolation, parameter validation, and execution timing.

        Returns:
            tuple[TaskStatusEnum, list[FindingItem], error_message | None, duration_ms]
        """
        start_time = time.perf_counter()
        try:
            clean_params = self.validate_parameters(parameters)
            findings = self.run_scan(clean_params, task_id, execution_id)
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return TaskStatusEnum.COMPLETED, findings, None, duration_ms
        except ValueError as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            err_msg = f"Scanner parameter validation failed: {exc}"
            logger.warning(
                "scanner_validation_failed",
                capability=self.capability.value,
                error=err_msg,
            )
            return TaskStatusEnum.FAILED, [], err_msg, duration_ms
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            err_msg = f"Scanner runtime exception: {exc}"
            logger.error(
                "scanner_execution_failed",
                capability=self.capability.value,
                error=err_msg,
            )
            return TaskStatusEnum.FAILED, [], err_msg, duration_ms
