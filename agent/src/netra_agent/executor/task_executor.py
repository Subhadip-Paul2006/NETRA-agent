"""Agent Task Executor Module for Phase 6 Security Scanner Subsystem."""

from typing import Any

from netra_shared.schemas.task import TaskStatusEnum

from netra_agent.scanners import global_registry


def execute_task(
    task_id: str,
    execution_id: str,
    capability: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Execute host agent task capability via registered scanner.

    Returns:
        dict containing status, execution_time_ms, findings, and error_message.
    """
    scanner = global_registry.get_scanner(capability)
    if not scanner:
        return {
            "status": TaskStatusEnum.FAILED,
            "execution_time_ms": 0,
            "findings": [],
            "error_message": f"Unsupported or unregistered capability '{capability}'.",
        }

    status, findings, error_msg, duration_ms = scanner.execute_with_safety_limits(
        parameters=parameters,
        task_id=task_id,
        execution_id=execution_id,
    )

    return {
        "status": status,
        "execution_time_ms": duration_ms,
        "findings": [f.model_dump() for f in findings],
        "error_message": error_msg,
    }


# Backwards compatibility alias for Phase 5 tests
execute_mock_task = execute_task
