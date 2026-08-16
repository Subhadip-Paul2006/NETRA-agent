"""Network Interface and Local Host Routing Security Scanner (SCAN_NETWORK)."""

import socket
from typing import Any

import psutil  # type: ignore[import-untyped]
from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner


class NetworkScanner(BaseScanner):
    """Scanner for local network interfaces, IP addresses, subnets, and DNS configuration."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_NETWORK

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(parameters, dict):
            raise ValueError("Parameters must be a dictionary.")
        # Reject shell execution payloads or forbidden parameter keys
        for key in parameters:
            if any(char in str(key) for char in (";", "|", "&", "`", "$", "\n")):
                raise ValueError(f"Illegal character in parameter key '{key}'.")
        return parameters

    def run_scan(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> list[FindingItem]:
        findings: list[FindingItem] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        interfaces_info: list[dict[str, Any]] = []

        for iface_name, iface_addrs in addrs.items():
            iface_stat = stats.get(iface_name)
            is_up = iface_stat.isup if iface_stat else False
            speed = iface_stat.speed if iface_stat else 0

            ip_list = []
            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ip_list.append({"ip": addr.address, "netmask": addr.netmask})

            interfaces_info.append(
                {
                    "interface": iface_name,
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "ipv4_addresses": ip_list,
                }
            )

            # Defensive Check: If active interface has public IP without firewall
            if is_up and ip_list:
                for item in ip_list:
                    ip_addr = item["ip"]
                    if not ip_addr.startswith(("127.", "10.", "172.16.", "192.168.", "169.254.")):
                        # Public IPv4 bound to local host
                        findings.append(
                            FindingItem(
                                title=f"Public IPv4 Address Assigned to Interface {iface_name}",
                                category="NETWORK_SECURITY",
                                severity="MEDIUM",
                                fingerprint=f"fp_net_public_ip_{iface_name}_{ip_addr}",
                                details={
                                    "interface": iface_name,
                                    "ip_address": ip_addr,
                                    "netmask": item.get("netmask"),
                                },
                            )
                        )

        # Baseline info finding
        hostname = socket.gethostname()
        findings.append(
            FindingItem(
                title=f"Local Host Network Adapter Reconnaissance ({hostname})",
                category="NETWORK_INVENTORY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_net_inv_{hostname}",
                details={
                    "hostname": hostname,
                    "interfaces_count": len(interfaces_info),
                    "interfaces": interfaces_info,
                },
            )
        )

        return findings
