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
class ProxyConfig:
    aws_gateway: AWSGatewayConfig = field(default_factory=AWSGatewayConfig)


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


def load_config() -> CloudSprayConfig:
    """Load AWS credentials from config.json.

    Looks for config.json in the current directory, then the repo root.
    If not found, returns defaults (Fireprox disabled).
    """
    config_path = Path("config.json")
    if not config_path.is_file():
        repo_root = Path(__file__).resolve().parent.parent
        config_path = repo_root / "config.json"

    if not config_path.is_file():
        return CloudSprayConfig()

    data = json.loads(config_path.read_text(encoding="utf-8"))

    access_key = data.get("aws_access_key", "")
    secret_key = data.get("aws_secret_key", "")
    regions = data.get("aws_regions", ["us-east-1", "us-west-2", "eu-west-1"])
    enabled = bool(access_key and secret_key)

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
                enabled=enabled,
                access_key=access_key,
                secret_key=secret_key,
                regions=regions,
            )
        ),
    )
