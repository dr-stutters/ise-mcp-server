"""Runtime settings: ISE_* for the appliance, MCP_* for this server (see stutters-mcp-core)."""

from pathlib import Path
from typing import ClassVar

from pydantic import Field, field_validator

from ise_mcp._core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("ISE_")
    # A second ISE (ISE_INSTANCES=prod) may run ERS on another port: never inherit it (core G10).
    per_instance_fields: ClassVar[frozenset[str]] = frozenset({"ers_port"})

    # ERS listens on 9060 on older releases and on 443 on newer ones (ISE 3.1+ can serve both).
    ers_port: int = Field(default=443, ge=1, le=65535, description="ERS API port (ISE_ERS_PORT)")
    # Status probes use a short timeout so a firewalled surface (e.g. 9060) doesn't stall startup.
    probe_timeout: float = Field(default=10.0, gt=0, description="Per-surface probe timeout (seconds)")
    # Large deployments: list tools fetch each ERS item for details only up to this many items, and
    # those per-item GETs run with this concurrency.
    detail_threshold: int = Field(
        default=100, ge=0, le=5000, description="Per-item ERS detail threshold (ISE_DETAIL_THRESHOLD)"
    )
    detail_concurrency: int = Field(
        default=5, ge=1, le=20, description="Concurrent per-item ERS GETs (ISE_DETAIL_CONCURRENCY)"
    )

    # ise_export_config / ise_diff_config (I42): when set, export files are written and read only inside
    # this directory (relative paths resolve against it). Unset: absolute *.yaml paths only.
    export_dir: Path | None = Field(
        default=None, description="Directory for config export files (ISE_EXPORT_DIR)"
    )

    @field_validator("export_dir", mode="before")
    @classmethod
    def _empty_dir_is_none(cls, v: object) -> object:
        if isinstance(v, str):
            return Path(v.strip()).expanduser() if v.strip() else None
        return v

    # --- product safety rails (I18, on top of core G7) ------------------------------------------
    # Protected endpoints/users/devices a disruptive action (CoA, ANC, NAD delete) is blocked on.
    # Comma-separated, matched case-insensitively (MACs are normalised).
    protect_macs: str = Field(default="", description="MACs never CoA'd/quarantined (ISE_PROTECT_MACS)")
    protect_users: str = Field(default="", description="Usernames never CoA'd (ISE_PROTECT_USERS)")
    protect_nads: str = Field(
        default="", description="NAD names/IPs never deleted or CoA'd via (ISE_PROTECT_NADS)"
    )
    # A port_bounce / port_shutdown CoA on a switch port with more than one live session takes every
    # endpoint on that port down (an uplink or trunk). Blocked unless this is set.
    coa_allow_shared_port: bool = Field(
        default=False, description="Allow port_bounce/shutdown on a shared port (ISE_COA_ALLOW_SHARED_PORT)"
    )
