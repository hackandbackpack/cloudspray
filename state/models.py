from dataclasses import dataclass, field
from datetime import datetime, timezone

from cloudspray.constants.error_codes import AuthResult


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


@dataclass
class SprayAttempt:
    """Single password spray attempt and its outcome."""

    username: str
    password: str
    client_id: str
    endpoint: str
    user_agent: str
    result: AuthResult
    error_code: str = ""
    timestamp: datetime = field(default_factory=_utcnow)
    proxy_used: str = ""


@dataclass
class ValidCredential:
    """A confirmed valid username/password pair."""

    username: str
    password: str
    result: AuthResult
    discovered_at: datetime = field(default_factory=_utcnow)
    mfa_type: str = ""


@dataclass
class Token:
    """OAuth token set obtained from a successful auth flow."""

    username: str
    access_token: str
    refresh_token: str
    id_token: str
    client_id: str
    resource: str
    expires_at: datetime | None = None
    is_foci: bool = False


@dataclass
class EnumResult:
    """Result from a user enumeration check."""

    username: str
    method: str
    exists: bool
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class LockedAccount:
    """Tracks an account that has been locked during spraying."""

    username: str
    locked_at: datetime = field(default_factory=_utcnow)
    attempt_count: int = 0
