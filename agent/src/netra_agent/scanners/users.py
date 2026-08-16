"""Host User Accounts and Session Security Posture Scanner (SCAN_USERS)."""

import os
from typing import Any

import psutil  # type: ignore[import-untyped]
from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner


class UsersScanner(BaseScanner):
    """Defensive scanner for local user accounts and active interactive sessions."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_USERS

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(parameters, dict):
            raise ValueError("Parameters must be a dictionary.")
        return parameters

    def run_scan(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> list[FindingItem]:
        findings: list[FindingItem] = []
        active_sessions: list[dict[str, Any]] = []

        try:
            current_user = os.getlogin()
        except Exception:
            current_user = "unknown"

        for u in psutil.users():
            active_sessions.append(
                {
                    "name": u.name,
                    "terminal": u.terminal or "N/A",
                    "host": u.host or "local",
                    "started_at": int(u.started),
                }
            )

            # Defensive Check: Guest or Default user active session
            if u.name.lower() in ("guest", "administrator", "root"):
                findings.append(
                    FindingItem(
                        title=f"Privileged or Default Account Active Session ({u.name})",
                        category="USER_ACCOUNT_SECURITY",
                        severity="MEDIUM",
                        fingerprint=f"fp_user_active_priv_{u.name}",
                        details={
                            "account_name": u.name,
                            "terminal": u.terminal,
                            "host": u.host,
                            "recommendation": (
                                "Restrict direct interactive logins to privileged accounts."
                            ),
                        },
                    )
                )

        findings.append(
            FindingItem(
                title=f"Local User Sessions Summary ({len(active_sessions)} Active Sessions)",
                category="USER_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_user_sum_{task_id[:8]}",
                details={
                    "current_process_user": current_user,
                    "active_sessions_count": len(active_sessions),
                    "active_sessions": active_sessions,
                },
            )
        )

        return findings
