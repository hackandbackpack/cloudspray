"""Configuration via config.json and CLI flags.

AWS credentials load from config.json in the repo root.
Everything else (domain, delay, jitter, etc.) comes from CLI flags.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetConfig:
    domain: str = ""


@dataclass
class SprayConfig:
    delay: int = 30
    jitter: int = 5
    lockout_threshold: int = 10
    lockout_cooldown: int = 1800
    shuffle_mode: str = "standard"


@dataclass
class AWSGatewayConfig:
    enabled: bool = False
    access_key: str = ""
    secret_key: str = ""
    regions: list[str] = field(
        default_factory=lambda: ["us-east-1", "us-west-2", "eu-west-1"]
    )


@dataclass
class AzureACIConfig:
    enabled: bool = False
    subscription_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    tenant_id: str = ""
    regions: list[str] = field(
        default_factory=lambda: ["eastus", "westus2", "westeurope"]
    )
    container_count: int = 3


@dataclass
class ProxyConfig:
    aws_gateway: AWSGatewayConfig = field(default_factory=AWSGatewayConfig)
    azure_aci: AzureACIConfig = field(default_factory=AzureACIConfig)


@dataclass
class EnumConfig:
    teams_user: str = ""
    teams_pass: str = ""


@dataclass
class CloudSprayConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    spray: SprayConfig = field(default_factory=SprayConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    enum: EnumConfig = field(default_factory=EnumConfig)


VALID_SHUFFLE_MODES = {"standard", "aggressive"}


def validate_shuffle_mode(value: str) -> str:
    """Validate shuffle mode, raising ValueError for invalid values."""
    if value not in VALID_SHUFFLE_MODES:
        raise ValueError(
            f"Invalid shuffle mode '{value}'. Must be one of: {', '.join(sorted(VALID_SHUFFLE_MODES))}"
        )
    return value


def load_config(config_path: str | None = None) -> CloudSprayConfig:
    """Load credentials and settings from config.json.

    Args:
        config_path: Explicit path to config.json. If provided, that file
            must exist or FileNotFoundError is raised. If ``None``, looks
            in the current directory then the repo root. Returns defaults
            when no config file is found.
    """
    if config_path is not None:
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        path = Path("config.json")
        if not path.is_file():
            repo_root = Path(__file__).resolve().parent.parent
            path = repo_root / "config.json"

    if not path.is_file():
        return CloudSprayConfig()

    data = json.loads(path.read_text(encoding="utf-8"))

    # AWS gateway credentials
    access_key = data.get("aws_access_key", "")
    secret_key = data.get("aws_secret_key", "")
    aws_regions = data.get("aws_regions", ["us-east-1", "us-west-2", "eu-west-1"])
    aws_enabled = bool(access_key and secret_key)

    # Azure ACI credentials
    azure_sub = data.get("azure_subscription_id", "")
    azure_client = data.get("azure_client_id", "")
    azure_secret = data.get("azure_client_secret", "")
    azure_tenant = data.get("azure_tenant_id", "")
    azure_regions = data.get(
        "azure_regions", ["eastus", "westus2", "westeurope"]
    )
    azure_count = data.get("azure_container_count", 3)
    azure_enabled = bool(azure_sub and azure_client and azure_secret and azure_tenant)

    # Spray settings from config.json (CLI flags override these)
    delay = data.get("delay", 30)
    jitter = data.get("jitter", 5)
    shuffle_mode = data.get("shuffle", "standard")
    lockout_threshold = data.get("lockout_threshold", 10)
    lockout_cooldown = data.get("lockout_cooldown", 1800)

    return CloudSprayConfig(
        spray=SprayConfig(
            delay=delay,
            jitter=jitter,
            lockout_threshold=lockout_threshold,
            lockout_cooldown=lockout_cooldown,
            shuffle_mode=shuffle_mode,
        ),
        proxy=ProxyConfig(
            aws_gateway=AWSGatewayConfig(
                enabled=aws_enabled,
                access_key=access_key,
                secret_key=secret_key,
                regions=aws_regions,
            ),
            azure_aci=AzureACIConfig(
                enabled=azure_enabled,
                subscription_id=azure_sub,
                client_id=azure_client,
                client_secret=azure_secret,
                tenant_id=azure_tenant,
                regions=azure_regions,
                container_count=azure_count,
            ),
        ),
    )
