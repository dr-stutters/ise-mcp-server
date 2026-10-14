"""Runtime settings: ISE_* for the appliance, MCP_* for this server (see stutters-mcp-core)."""

from pydantic import Field
from stutters_mcp_core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("ISE_")

    # ERS listens on 9060 on older releases and on 443 on newer ones (ISE 3.1+ can serve both).
    ers_port: int = Field(default=443, ge=1, le=65535, description="ERS API port (ISE_ERS_PORT)")
    # Status probes use a short timeout so a firewalled surface (e.g. 9060) doesn't stall startup.
    probe_timeout: float = Field(default=10.0, gt=0, description="Per-surface probe timeout (seconds)")
