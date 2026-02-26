from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class TargetConfig:
    """Target domain configuration."""

    domain: str = ""


@dataclass
class SprayConfig:
    """Password spray timing and safety parameters."""

    delay: int = 30
    jitter: int = 5
    lockout_threshold: int = 5
    lockout_pause: int = 900
    shuffle_mode: str = "standard"


@dataclass
class AWSGatewayConfig:
    """AWS API Gateway proxy settings."""

    enabled: bool = False
    access_key: str = ""
    secret_key: str = ""
    regions: list[str] = field(
        default_factory=lambda: ["us-east-1", "us-west-2", "eu-west-1"]
    )


@dataclass
class AzureACIConfig:
    """Azure Container Instance proxy settings."""

    enabled: bool = False
    subscription_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    tenant_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["eastus", "westus2"])
    container_count: int = 3


@dataclass
class ProxyListConfig:
    """Static proxy list file settings."""

    enabled: bool = False
    file: str = "proxies.txt"


@dataclass
class ProxyConfig:
    """All proxy rotation settings."""

    aws_gateway: AWSGatewayConfig = field(default_factory=AWSGatewayConfig)
    azure_aci: AzureACIConfig = field(default_factory=AzureACIConfig)
    proxy_list: ProxyListConfig = field(default_factory=ProxyListConfig)


@dataclass
class EnumConfig:
    """Teams enumeration credentials."""

    teams_user: str = ""
    teams_pass: str = ""


@dataclass
class CloudSprayConfig:
    """Top-level configuration combining all sections."""

    target: TargetConfig = field(default_factory=TargetConfig)
    spray: SprayConfig = field(default_factory=SprayConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    enum: EnumConfig = field(default_factory=EnumConfig)


VALID_SHUFFLE_MODES = {"standard", "aggressive"}


def _merge_dict(defaults: dict, overrides: dict) -> dict:
    """Recursively merge overrides into defaults, returning a new dict."""
    merged = dict(defaults)
    for key, value in overrides.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _defaults_dict() -> dict:
    """Return the full config structure as a plain dict with all defaults."""
    config = CloudSprayConfig()
    return {
        "target": {"domain": config.target.domain},
        "spray": {
            "delay": config.spray.delay,
            "jitter": config.spray.jitter,
            "lockout_threshold": config.spray.lockout_threshold,
            "lockout_pause": config.spray.lockout_pause,
            "shuffle_mode": config.spray.shuffle_mode,
        },
        "proxy": {
            "aws_gateway": {
                "enabled": config.proxy.aws_gateway.enabled,
                "access_key": config.proxy.aws_gateway.access_key,
                "secret_key": config.proxy.aws_gateway.secret_key,
                "regions": list(config.proxy.aws_gateway.regions),
            },
            "azure_aci": {
                "enabled": config.proxy.azure_aci.enabled,
                "subscription_id": config.proxy.azure_aci.subscription_id,
                "client_id": config.proxy.azure_aci.client_id,
                "client_secret": config.proxy.azure_aci.client_secret,
                "tenant_id": config.proxy.azure_aci.tenant_id,
                "regions": list(config.proxy.azure_aci.regions),
                "container_count": config.proxy.azure_aci.container_count,
            },
            "proxy_list": {
                "enabled": config.proxy.proxy_list.enabled,
                "file": config.proxy.proxy_list.file,
            },
        },
        "enum": {
            "teams_user": config.enum.teams_user,
            "teams_pass": config.enum.teams_pass,
        },
    }


def _build_config(data: dict) -> CloudSprayConfig:
    """Build a CloudSprayConfig from a flat merged dict."""
    target_data = data.get("target", {})
    spray_data = data.get("spray", {})
    proxy_data = data.get("proxy", {})
    enum_data = data.get("enum", {})

    aws_data = proxy_data.get("aws_gateway", {})
    aci_data = proxy_data.get("azure_aci", {})
    plist_data = proxy_data.get("proxy_list", {})

    return CloudSprayConfig(
        target=TargetConfig(**target_data),
        spray=SprayConfig(**spray_data),
        proxy=ProxyConfig(
            aws_gateway=AWSGatewayConfig(**aws_data),
            azure_aci=AzureACIConfig(**aci_data),
            proxy_list=ProxyListConfig(**plist_data),
        ),
        enum=EnumConfig(**enum_data),
    )


def _validate(config: CloudSprayConfig) -> None:
    """Validate the config, raising ValueError for any issues."""
    if config.spray.shuffle_mode not in VALID_SHUFFLE_MODES:
        raise ValueError(
            f"Invalid shuffle_mode '{config.spray.shuffle_mode}'. "
            f"Must be one of: {', '.join(sorted(VALID_SHUFFLE_MODES))}"
        )

    if config.spray.delay < 0:
        raise ValueError(f"spray.delay must be >= 0, got {config.spray.delay}")

    if config.spray.jitter < 0:
        raise ValueError(f"spray.jitter must be >= 0, got {config.spray.jitter}")

    if config.spray.lockout_threshold < 1:
        raise ValueError(
            f"spray.lockout_threshold must be >= 1, got {config.spray.lockout_threshold}"
        )

    if config.spray.lockout_pause < 0:
        raise ValueError(
            f"spray.lockout_pause must be >= 0, got {config.spray.lockout_pause}"
        )

    if config.proxy.azure_aci.container_count < 1:
        raise ValueError(
            f"proxy.azure_aci.container_count must be >= 1, "
            f"got {config.proxy.azure_aci.container_count}"
        )


def load_config(path: str | None = None) -> CloudSprayConfig:
    """Load configuration from a YAML file, merging with defaults.

    If no path is provided, returns a config with all defaults.
    """
    defaults = _defaults_dict()

    if path is None:
        return _build_config(defaults)

    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_yaml = config_path.read_text(encoding="utf-8")
    user_data = yaml.safe_load(raw_yaml)

    if not isinstance(user_data, dict):
        raise ValueError(f"Config file must contain a YAML mapping, got {type(user_data).__name__}")

    merged = _merge_dict(defaults, user_data)
    config = _build_config(merged)
    _validate(config)

    return config
