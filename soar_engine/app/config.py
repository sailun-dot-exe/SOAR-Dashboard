"""Application settings loaded from environment variables (prefix ``SOAR_``)."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOAR_", env_file=".env", extra="ignore")

    # --- Core ---------------------------------------------------------------
    app_name: str = "Wazuh SOAR Engine"
    log_level: str = "INFO"
    database_url: str = "sqlite+aiosqlite:///./soar.db"
    playbook_dir: Path = Path(__file__).resolve().parent.parent / "playbooks"
    public_base_url: str = "http://localhost:8000"

    # --- Security -----------------------------------------------------------
    api_token: SecretStr = Field(..., description="Shared secret expected in X-SOAR-Token.")
    admin_token: SecretStr = Field(..., description="Token for read/admin APIs (X-Admin-Token).")
    hitl_signing_key: SecretStr = Field(..., description="HMAC key used to sign HITL links.")
    protected_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"],
        description="Source IPs inside these networks are never blocked.",
    )

    # --- HITL ---------------------------------------------------------------
    hitl_timeout_seconds: int = 300
    hitl_auto_execute_level: int = 12
    sweeper_interval_seconds: float = 2.0
    notification_timeout_seconds: float = 1.5

    slack_webhook_url: SecretStr | None = None

    smtp_host: str | None = None
    smtp_port: int = 25
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = False
    smtp_from: str = "soar@localhost"
    smtp_to: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Retry policy -------------------------------------------------------
    retry_max_retries: int = 3
    retry_backoff_seconds: float = 0.5

    # --- Wazuh Manager REST API --------------------------------------------
    wazuh_api_url: str = "https://wazuh-manager:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: SecretStr = SecretStr("")
    wazuh_verify_ssl: bool = False
    wazuh_request_timeout: float = 10.0

    # --- SSH direct agent ---------------------------------------------------
    ssh_username: str = "soar"
    ssh_key_path: Path | None = None
    ssh_password: SecretStr | None = None
    ssh_port: int = 22
    ssh_known_hosts: Path | None = None
    ssh_connect_timeout: float = 5.0

    # --- Docker Engine API (through a socket proxy) -------------------------
    docker_api_url: str = "http://docker-proxy:2375"
    docker_request_timeout: float = 10.0

    @field_validator("protected_cidrs", "smtp_to", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("protected_cidrs")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            ipaddress.ip_network(cidr, strict=False)
        return value

    def is_protected_ip(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in self.protected_cidrs)


@lru_cache
def get_settings() -> Settings:
    return Settings()
