"""YAML-based configuration with dataclass defaults and deep merge.

CloudSpray uses a layered configuration approach:

1. **Dataclass defaults** -- Every config field has a sensible default defined
   in a hierarchy of ``@dataclass`` classes (``TargetConfig``, ``SprayConfig``,
   ``ProxyConfig``, etc.) rolled up into the top-level ``CloudSprayConfig``.

2. **YAML file overrides** -- The user can supply a YAML config file that
   specifies only the fields they want to change. The YAML is recursively
   merged on top of the defaults so unspecified fields keep their defaults.

3. **CLI overrides** -- Individual CLI flags (e.g. ``--delay``, ``--jitter``)
   are applied on top of the merged config inside the CLI layer (see cli.py).

The merge strategy (``_merge_dict``) walks both dicts recursively: when both
the default and the override have a dict for the same key, they merge
recursively; otherwise the override wins. This lets the user write a partial
YAML like::

    spray:
      delay: 60

and have every other field keep its default value.

After merging, the config is validated (``_validate``) to catch obviously
wrong values (negative delays, invalid shuffle modes, etc.) before any
network operations start.

Typical usage::

    config = load_config("config.yaml")  # merge YAML over defaults
    config = load_config()               # all defaults, no file
"""

import dataclasses
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class TargetConfig:
    """Target domain configuration.

    Attributes:
        domain: The Azure AD / M365 tenant domain (e.g. "contoso.com").
            Typically set via ``--domain`` on the CLI rather than the config file.
    """

    domain: str = ""


@dataclass
class SprayConfig:
    """Password spray timing and safety parameters.

    These control the pace and safety behavior of the spray engine
    to balance speed against account lockout risk.

    Attributes:
        delay: Base seconds to wait between spray attempts per user.
        jitter: Maximum random seconds added to delay for timing randomization.
        lockout_threshold: Hard stop -- abort the spray if this many accounts
            are locked in a single round.
        lockout_cooldown: Seconds to pause per-user after a lockout is detected
            before retrying that account. Default 1800 (30 minutes).
        shuffle_mode: Controls how user/password pairs are ordered.
            "standard" shuffles users within each password round.
            "aggressive" shuffles both users and passwords together.
    """

    delay: int = 30
    jitter: int = 5
    lockout_threshold: int = 10
    lockout_cooldown: int = 1800
    shuffle_mode: str = "standard"


@dataclass
class AWSGatewayConfig:
    """AWS API Gateway (Fireprox) proxy settings.

    When enabled, CloudSpray creates temporary API Gateway endpoints
    that proxy requests to Microsoft login servers, rotating the source
    IP across AWS regions. This is the primary IP rotation strategy.

    Attributes:
        enabled: Whether to use Fireprox proxy rotation.
        access_key: AWS IAM access key ID.
        secret_key: AWS IAM secret access key.
        regions: AWS regions to deploy gateway endpoints in. More regions
            means more source IPs but higher setup/teardown time.
    """

    enabled: bool = False
    access_key: str = ""
    secret_key: str = ""
    regions: list[str] = field(
        default_factory=lambda: ["us-east-1", "us-west-2", "eu-west-1"]
    )


@dataclass
class AzureACIConfig:
    """Azure Container Instance proxy settings.

    An alternative to Fireprox that deploys lightweight containers in Azure
    to relay spray traffic through different Azure public IPs.

    Attributes:
        enabled: Whether to use ACI-based proxy rotation.
        subscription_id: Azure subscription ID.
        client_id: Azure AD app registration client ID for ACI management.
        client_secret: Corresponding client secret.
        tenant_id: Azure AD tenant ID for the service principal.
        regions: Azure regions to deploy containers in.
        container_count: Number of containers per region.
    """

    enabled: bool = False
    subscription_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    tenant_id: str = ""
    regions: list[str] = field(default_factory=lambda: ["eastus", "westus2"])
    container_count: int = 3


@dataclass
class ProxyListConfig:
    """Static proxy list file settings.

    For users who already have a pool of SOCKS5/HTTP proxies, this
    config points to a file with one proxy URL per line.

    Attributes:
        enabled: Whether to load and rotate through the proxy list.
        file: Path to the proxy list file.
    """

    enabled: bool = False
    file: str = "proxies.txt"


@dataclass
class ProxyConfig:
    """Container for all proxy rotation backends.

    Only one proxy backend should be enabled at a time. If multiple
    are enabled, the ProxyManager will combine them.

    Attributes:
        aws_gateway: Fireprox (AWS API Gateway) configuration.
        azure_aci: Azure Container Instance proxy configuration.
        proxy_list: Static proxy list configuration.
    """

    aws_gateway: AWSGatewayConfig = field(default_factory=AWSGatewayConfig)
    azure_aci: AzureACIConfig = field(default_factory=AzureACIConfig)
    proxy_list: ProxyListConfig = field(default_factory=ProxyListConfig)


@dataclass
class EnumConfig:
    """Credentials used for Teams-based user enumeration.

    The Teams enumeration method requires a valid M365 account to
    authenticate and query the Teams user presence API.

    Attributes:
        teams_user: Username (email) of the authenticated Teams account.
        teams_pass: Password for the Teams account.
    """

    teams_user: str = ""
    teams_pass: str = ""


@dataclass
class CloudSprayConfig:
    """Top-level configuration combining all sections.

    This is the single config object passed throughout the application.
    It is constructed by :func:`load_config` which merges YAML overrides
    on top of dataclass defaults.

    Attributes:
        target: Target domain settings.
        spray: Spray timing and lockout parameters.
        proxy: Proxy rotation backend settings.
        enum: Teams enumeration credentials.
    """

    target: TargetConfig = field(default_factory=TargetConfig)
    spray: SprayConfig = field(default_factory=SprayConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    enum: EnumConfig = field(default_factory=EnumConfig)


VALID_SHUFFLE_MODES = {"standard", "aggressive"}


def _merge_dict(defaults: dict, overrides: dict) -> dict:
    """Recursively merge *overrides* into *defaults*, returning a new dict.

    When both sides have a dict for the same key, the merge recurses into
    that sub-dict so nested values are preserved. For all other types the
    override value replaces the default outright.

    Args:
        defaults: Base dictionary with all default values.
        overrides: User-supplied dictionary (from parsed YAML).

    Returns:
        A new dict combining both inputs (neither input is mutated).
    """
    merged = dict(defaults)
    for key, value in overrides.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _defaults_dict() -> dict:
    """Return the full config structure as a plain dict with all defaults.

    This converts a default-constructed ``CloudSprayConfig`` to a dict using
    ``dataclasses.asdict`` so it can be used as the base layer in the merge.

    Returns:
        Nested dict mirroring the dataclass hierarchy with all default values.
    """
    return dataclasses.asdict(CloudSprayConfig())


def _filter_fields(cls: type, data: dict) -> dict:
    """Keep only keys that match known dataclass fields, warn about extras.

    This prevents ``TypeError`` when constructing dataclasses from YAML data
    that may contain typos or unknown keys. Any extra keys are logged as
    warnings so the user knows their config entry was ignored.

    Args:
        cls: The dataclass type to filter against.
        data: Dict of key/value pairs to filter.

    Returns:
        A new dict containing only the keys that are valid fields of *cls*.
    """
    known = {f.name for f in dataclasses.fields(cls)}
    filtered = {}
    for key, value in data.items():
        if key in known:
            filtered[key] = value
        else:
            logger.warning("Ignoring unknown config key '%s' for %s", key, cls.__name__)
    return filtered


def _build_config(data: dict) -> CloudSprayConfig:
    """Build a ``CloudSprayConfig`` from a flat merged dict.

    Walks the nested dict structure, constructing each dataclass from the
    bottom up. Unknown keys are filtered out at each level via
    :func:`_filter_fields`.

    Args:
        data: Merged dict (defaults + user overrides) with the full config.

    Returns:
        A fully constructed ``CloudSprayConfig`` instance.
    """
    target_data = data.get("target", {})
    spray_data = data.get("spray", {})
    proxy_data = data.get("proxy", {})
    enum_data = data.get("enum", {})

    # Proxy has nested sub-sections that need individual construction
    aws_data = proxy_data.get("aws_gateway", {})
    aci_data = proxy_data.get("azure_aci", {})
    plist_data = proxy_data.get("proxy_list", {})

    return CloudSprayConfig(
        target=TargetConfig(**_filter_fields(TargetConfig, target_data)),
        spray=SprayConfig(**_filter_fields(SprayConfig, spray_data)),
        proxy=ProxyConfig(
            aws_gateway=AWSGatewayConfig(**_filter_fields(AWSGatewayConfig, aws_data)),
            azure_aci=AzureACIConfig(**_filter_fields(AzureACIConfig, aci_data)),
            proxy_list=ProxyListConfig(**_filter_fields(ProxyListConfig, plist_data)),
        ),
        enum=EnumConfig(**_filter_fields(EnumConfig, enum_data)),
    )


def _validate(config: CloudSprayConfig) -> None:
    """Validate the config, raising ``ValueError`` for any issues.

    Called after building the config to catch obviously wrong values
    before any network operations begin.

    Args:
        config: The fully constructed config to validate.

    Raises:
        ValueError: If any field has an invalid value (e.g. negative delay,
            unknown shuffle mode, container count < 1).
    """
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

    if config.spray.lockout_cooldown < 0:
        raise ValueError(
            f"spray.lockout_cooldown must be >= 0, got {config.spray.lockout_cooldown}"
        )

    if config.proxy.azure_aci.container_count < 1:
        raise ValueError(
            f"proxy.azure_aci.container_count must be >= 1, "
            f"got {config.proxy.azure_aci.container_count}"
        )


def load_config(path: str | None = None) -> CloudSprayConfig:
    """Load configuration from a YAML file, merging with defaults.

    This is the main entry point for config loading. It implements the
    three-step process:

    1. Build a dict of all defaults from the dataclass hierarchy
    2. If a YAML path is given, parse it and deep-merge over defaults
    3. Validate the final config before returning

    If no path is provided, returns a config with all defaults.

    Args:
        path: Optional path to a YAML config file. If ``None``, all
            defaults are used.

    Returns:
        A validated ``CloudSprayConfig`` instance.

    Raises:
        FileNotFoundError: If the specified config file does not exist.
        ValueError: If the YAML is not a mapping or validation fails.
    """
    defaults = _defaults_dict()

    if path is None:
        config = _build_config(defaults)
        _validate(config)
        return config

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
