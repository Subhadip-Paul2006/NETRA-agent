"""NETRA Backend Health & Readiness Probes Endpoint Module.

Implements liveness (health) and readiness endpoints following k8s / Cloud native standards:
- GET /api/v1/health: Liveness probe indicating process is alive.
- GET /api/v1/readiness: Readiness probe indicating service readiness to serve traffic.
"""

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Response, status

router = APIRouter(tags=["Health & Monitoring"])


class ReadinessCheckManager:
    """Extensible registry for subsystem readiness checks."""

    def __init__(self) -> None:
        self._checks: dict[str, Callable[[], Awaitable[bool] | bool]] = {}

    def register(self, name: str, check_fn: Callable[[], Awaitable[bool] | bool]) -> None:
        """Register a readiness check function."""
        self._checks[name] = check_fn

    def unregister(self, name: str) -> None:
        """Unregister a readiness check function."""
        self._checks.pop(name, None)

    async def run_checks(self) -> tuple[bool, dict[str, str]]:
        """Execute all registered readiness checks."""
        results: dict[str, str] = {"app": "ok"}
        all_ready = True

        for name, check_fn in self._checks.items():
            try:
                res = check_fn()
                if inspect.isawaitable(res):
                    is_ok = await res
                else:
                    is_ok = bool(res)

                if is_ok:
                    results[name] = "ok"
                else:
                    results[name] = "failed"
                    all_ready = False
            except Exception:
                results[name] = "error"
                all_ready = False

        return all_ready, results


readiness_manager = ReadinessCheckManager()


@router.get("/health", summary="Liveness Probe")
async def health_check() -> dict[str, str]:
    """Liveness probe confirming the backend process is running."""
    return {
        "status": "UP",
        "service": "netra-backend",
    }


@router.get("/readiness", summary="Readiness Probe")
async def readiness_check(response: Response) -> dict[str, Any]:
    """Readiness probe confirming the service is ready to process requests."""
    is_ready, checks = await readiness_manager.run_checks()

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "READY" if is_ready else "NOT_READY",
        "service": "netra-backend",
        "checks": checks,
    }
