"""Host System Firewall Posture Scanner (SCAN_FIREWALL)."""

import shutil
import subprocess
import sys
from typing import Any

from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner


class FirewallScanner(BaseScanner):
    """Defensive scanner for host firewall configuration and active profile status."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_FIREWALL

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
        platform = sys.platform
        fw_status = "UNKNOWN"
        details: dict[str, Any] = {"platform": platform}

        if platform == "win32":
            # Inspect Windows Firewall via hardcoded netsh CLI
            netsh_path = shutil.which("netsh")
            if netsh_path:
                try:
                    res = subprocess.run(
                        [netsh_path, "advfirewall", "show", "allprofiles", "state"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    stdout = res.stdout
                    details["raw_output"] = stdout[:1000]
                    if "OFF" in stdout.upper():
                        fw_status = "DISABLED"
                    elif "ON" in stdout.upper():
                        fw_status = "ENABLED"
                except Exception as exc:
                    details["error"] = str(exc)

        elif platform.startswith("linux"):
            # Inspect Linux ufw / iptables
            ufw_path = shutil.which("ufw")
            if ufw_path:
                try:
                    res = subprocess.run(
                        [ufw_path, "status"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    stdout = res.stdout
                    details["ufw_output"] = stdout[:1000]
                    if "active" in stdout.lower() and "inactive" not in stdout.lower():
                        fw_status = "ENABLED"
                    elif "inactive" in stdout.lower():
                        fw_status = "DISABLED"
                except Exception as exc:
                    details["error"] = str(exc)

        elif platform == "darwin":
            # Inspect macOS pfctl
            pfctl_path = shutil.which("pfctl")
            if pfctl_path:
                try:
                    res = subprocess.run(
                        [pfctl_path, "-s", "info"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    stdout = res.stdout
                    details["pfctl_output"] = stdout[:1000]
                    if "Enabled" in stdout:
                        fw_status = "ENABLED"
                    elif "Disabled" in stdout:
                        fw_status = "DISABLED"
                except Exception as exc:
                    details["error"] = str(exc)

        if fw_status == "DISABLED":
            findings.append(
                FindingItem(
                    title="Host Firewall is Currently Disabled",
                    category="FIREWALL_SECURITY",
                    severity="HIGH",
                    fingerprint=f"fp_fw_disabled_{platform}",
                    details={
                        "platform": platform,
                        "status": "DISABLED",
                        "recommendation": "Enable host firewall.",
                    },
                )
            )

        findings.append(
            FindingItem(
                title=f"Host Firewall Status Inspection ({platform.upper()}: {fw_status})",
                category="FIREWALL_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_fw_inv_{platform}",
                details={
                    "platform": platform,
                    "firewall_status": fw_status,
                    "metadata": details,
                },
            )
        )

        return findings
