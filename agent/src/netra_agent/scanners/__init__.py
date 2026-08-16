"""NETRA Host Agent Scanner Engine Subsystem.

Provides 7 defensive capability scanners registered in ScannerRegistry.
"""

from netra_agent.scanners.base import BaseScanner
from netra_agent.scanners.connections import ConnectionsScanner
from netra_agent.scanners.file_integrity import FileIntegrityScanner
from netra_agent.scanners.firewall import FirewallScanner
from netra_agent.scanners.network import NetworkScanner
from netra_agent.scanners.processes import ProcessScanner
from netra_agent.scanners.registry import ScannerRegistry, global_registry
from netra_agent.scanners.startup import StartupScanner
from netra_agent.scanners.users import UsersScanner

# Register all 7 scanners automatically into global_registry
_scanners_to_register = [
    NetworkScanner(),
    ProcessScanner(),
    ConnectionsScanner(),
    FirewallScanner(),
    UsersScanner(),
    StartupScanner(),
    FileIntegrityScanner(),
]

for _scanner in _scanners_to_register:
    if not global_registry.is_registered(_scanner.capability):
        global_registry.register(_scanner)

__all__ = [
    "BaseScanner",
    "ScannerRegistry",
    "global_registry",
    "NetworkScanner",
    "ProcessScanner",
    "ConnectionsScanner",
    "FirewallScanner",
    "UsersScanner",
    "StartupScanner",
    "FileIntegrityScanner",
]
