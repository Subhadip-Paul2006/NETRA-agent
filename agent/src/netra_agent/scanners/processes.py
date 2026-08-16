"""Process Execution and Security Posture Scanner (SCAN_PROCESSES)."""

from typing import Any

import psutil  # type: ignore[import-untyped]
from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner


class ProcessScanner(BaseScanner):
    """Defensive scanner for host process table inspection."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_PROCESSES

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(parameters, dict):
            raise ValueError("Parameters must be a dictionary.")
        max_procs = parameters.get("max_processes", 500)
        if not isinstance(max_procs, int) or max_procs <= 0 or max_procs > 5000:
            raise ValueError("max_processes must be an integer between 1 and 5000.")
        return parameters

    def run_scan(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> list[FindingItem]:
        findings: list[FindingItem] = []
        max_procs = parameters.get("max_processes", 500)

        process_count = 0
        suspicious_procs = []

        # Iterate over processes safely
        for proc in psutil.process_iter(["pid", "name", "username", "ppid", "create_time"]):
            if process_count >= max_procs:
                break
            process_count += 1

            try:
                pinfo = proc.info
                pid = pinfo["pid"]
                name = pinfo["name"] or "unknown"
                username = pinfo["username"] or "N/A"
                ppid = pinfo["ppid"]

                # Defensive check: Unnamed process or suspicious temp directory execution
                if name == "unknown" or name.strip() == "":
                    suspicious_procs.append({"pid": pid, "reason": "Unnamed process entry"})
                elif any(
                    temp_dir in name.lower()
                    for temp_dir in ("\\temp\\", "/tmp/", "\\appdata\\local\\temp")
                ):
                    suspicious_procs.append(
                        {
                            "pid": pid,
                            "name": name,
                            "user": username,
                            "ppid": ppid,
                            "reason": "Process binary executing from temporary directory",
                        }
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if suspicious_procs:
            for item in suspicious_procs:
                pid = item["pid"]
                reason = item["reason"]
                name = item.get("name", "unknown")
                findings.append(
                    FindingItem(
                        title=f"Suspicious Process Execution Detected (PID {pid}: {name})",
                        category="PROCESS_SECURITY",
                        severity="MEDIUM",
                        fingerprint=f"fp_proc_suspicious_{pid}_{name}",
                        details={
                            "pid": pid,
                            "name": name,
                            "reason": reason,
                            "user": item.get("user", "N/A"),
                            "ppid": item.get("ppid"),
                        },
                    )
                )

        findings.append(
            FindingItem(
                title=f"Host Running Process Summary ({process_count} Active Processes)",
                category="PROCESS_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_proc_sum_{task_id[:8]}",
                details={
                    "total_inspected_processes": process_count,
                    "suspicious_count": len(suspicious_procs),
                },
            )
        )

        return findings
