"""Configuration via .env file and CLI flags.

AWS credentials load from a .env file (or environment variables).
Everything else (domain, delay, jitter, etc.) comes from CLI flags.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


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
    """Load config from .env file and environment variables.

    Looks for .env in the current directory, then the repo root.
    AWS credentials come from: AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGIONS
    """
    env_path = Path(".env")
    if not env_path.is_file():
        repo_root = Path(__file__).resolve().parent.parent
        env_path = repo_root / ".env"

    load_dotenv(env_path)

    access_key = os.getenv("AWS_ACCESS_KEY", "")
    secret_key = os.getenv("AWS_SECRET_KEY", "")
    regions_str = os.getenv("AWS_REGIONS", "us-east-1,us-west-2,eu-west-1")
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]

    enabled = bool(access_key and secret_key)

    return CloudSprayConfig(
        proxy=ProxyConfig(
            aws_gateway=AWSGatewayConfig(
                enabled=enabled,
                access_key=access_key,
                secret_key=secret_key,
                regions=regions,
            )
        )
    )
