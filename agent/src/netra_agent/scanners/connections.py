"""Network Socket and Active Connection Security Scanner (SCAN_CONNECTIONS)."""

from typing import Any

import psutil  # type: ignore[import-untyped]
from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner

HIGH_RISK_PORTS = {
    21: ("FTP", "HIGH"),
    23: ("Telnet", "HIGH"),
    445: ("SMB", "MEDIUM"),
    3389: ("RDP", "LOW"),
    5900: ("VNC", "MEDIUM"),
}


class ConnectionsScanner(BaseScanner):
    """Defensive scanner for active network connections and listening ports."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_CONNECTIONS

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
        listening_ports: list[dict[str, Any]] = []

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            conns = []

        for conn in conns:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                lport = conn.laddr.port
                lhost = conn.laddr.ip

                listening_ports.append(
                    {
                        "host": lhost,
                        "port": lport,
                        "pid": conn.pid,
                        "family": str(conn.family),
                    }
                )

                # Defensive Check: Unencrypted or risky service listening publicly (0.0.0.0 or ::)
                if lport in HIGH_RISK_PORTS and lhost in ("0.0.0.0", "::", ""):
                    svc_name, default_sev = HIGH_RISK_PORTS[lport]
                    findings.append(
                        FindingItem(
                            title=f"High-Risk Listening Port: {svc_name} ({lport})",
                            category="NETWORK_PORT_SECURITY",
                            severity=default_sev,
                            fingerprint=f"fp_conn_listen_{svc_name.lower()}_{lport}",
                            details={
                                "service": svc_name,
                                "bind_host": lhost,
                                "port": lport,
                                "pid": conn.pid,
                                "recommendation": (
                                    f"Ensure {svc_name} service on port {lport} is restricted."
                                ),
                            },
                        )
                    )

        findings.append(
            FindingItem(
                title=f"Active Network Sockets Summary ({len(listening_ports)} Listening Ports)",
                category="NETWORK_PORT_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_conn_sum_{task_id[:8]}",
                details={
                    "total_connections": len(conns),
                    "listening_ports_count": len(listening_ports),
                    "listening_ports": listening_ports[:50],  # Bound details size
                },
            )
        )

        return findings
