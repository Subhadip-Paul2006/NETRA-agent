"""System Persistence and Startup Mechanisms Scanner (SCAN_STARTUP)."""

import os
import sys
from typing import Any

from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner


class StartupScanner(BaseScanner):
    """Defensive scanner for host autorun, systemd, and startup locations."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_STARTUP

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
        startup_items: list[dict[str, Any]] = []

        platform = sys.platform

        if platform == "win32":
            try:
                import winreg

                key_paths = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                ]
                for root_key, subkey in key_paths:
                    try:
                        with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                            idx = 0
                            while True:
                                try:
                                    val_name, val_data, _ = winreg.EnumValue(key, idx)
                                    startup_items.append(
                                        {
                                            "name": val_name,
                                            "path": str(val_data),
                                            "location": subkey,
                                        }
                                    )
                                    idx += 1
                                except OSError:
                                    break
                    except Exception:
                        continue
            except ImportError:
                pass

        elif platform.startswith("linux"):
            cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system"]
            for cdir in cron_dirs:
                if os.path.exists(cdir) and os.path.isdir(cdir):
                    try:
                        entries = os.listdir(cdir)[:20]
                        for entry in entries:
                            startup_items.append({"name": entry, "location": cdir})
                    except Exception:
                        continue

        # Check for items executing from temp locations
        for item in startup_items:
            path_str = str(item.get("path", "")).lower()
            if any(t in path_str for t in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp")):
                findings.append(
                    FindingItem(
                        title=f"Suspicious Temp Directory Startup ({item.get('name')})",
                        category="PERSISTENCE_SECURITY",
                        severity="HIGH",
                        fingerprint=f"fp_startup_temp_{item.get('name')}",
                        details={
                            "name": item.get("name"),
                            "path": item.get("path"),
                            "location": item.get("location"),
                            "recommendation": (
                                "Inspect validity of startup app executing from temp folder."
                            ),
                        },
                    )
                )

        findings.append(
            FindingItem(
                title=f"Host Startup Inventory Summary ({len(startup_items)} Startup Entries)",
                category="STARTUP_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_startup_sum_{task_id[:8]}",
                details={
                    "platform": platform,
                    "entries_count": len(startup_items),
                    "items": startup_items[:50],
                },
            )
        )

        return findings
