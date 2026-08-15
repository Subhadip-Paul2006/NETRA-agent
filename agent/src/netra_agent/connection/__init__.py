"""NETRA Host Security Agent Network Connection Package."""

from netra_agent.connection.rest_client import AgentRESTClient
from netra_agent.connection.wss_client import AgentWSSClient

__all__ = ["AgentRESTClient", "AgentWSSClient"]
