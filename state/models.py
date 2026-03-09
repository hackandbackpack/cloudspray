"""Data models for all records persisted in the state database.

These dataclasses define the structured records that flow between the spray
engine, enumeration modules, post-exploitation tools, and the SQLite
database layer. They are the canonical in-memory representation of each
row in the database.

All timestamp fields default to the current UTC time via :func:`_utcnow`,
and ``AuthResult`` enum values are stored as their string ``.value`` in
the database (e.g. ``"success"``, ``"valid_password_mfa_required"``).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from cloudspray.constants.error_codes import AuthResult


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    Used as the ``default_factory`` for timestamp fields so every record
    gets an accurate creation time without requiring the caller to pass one.

    Returns:
        Current UTC datetime with timezone info attached.
    """
    return datetime.now(timezone.utc)


@dataclass
class SprayAttempt:
    """Single password spray attempt and its outcome.

    One of these is created for every authentication request sent to Azure AD,
    regardless of the result. Stored in the ``spray_attempts`` table.

    Attributes:
        username: Target email address (e.g. "user@contoso.com").
        password: Password that was tried.
        client_id: OAuth client ID used for the attempt (rotated for evasion).
        endpoint: The Microsoft endpoint URL targeted.
        user_agent: HTTP User-Agent header sent with the request.
        result: Classified outcome from :class:`AuthResult`.
        error_code: Raw AADSTS error code string from Azure AD (if any).
        timestamp: When the attempt was made (UTC).
        proxy_used: Proxy URL used for this attempt, or empty if direct.
    """

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
    """A confirmed valid username/password pair.

    Created when a spray attempt returns any "valid password" result,
    including SUCCESS, MFA_REQUIRED, MFA_ENROLLMENT, CA_BLOCKED, or
    PASSWORD_EXPIRED. Stored in the ``valid_credentials`` table.

    Attributes:
        username: The email address with a valid password.
        password: The confirmed working password.
        result: The specific auth result indicating what happens after login
            (e.g. MFA prompt, conditional access block, or clean success).
        discovered_at: When the credential was confirmed (UTC).
        mfa_type: Type of MFA enforced (e.g. "push", "totp"), if detectable.
    """

    username: str
    password: str
    result: AuthResult
    discovered_at: datetime = field(default_factory=_utcnow)
    mfa_type: str = ""


@dataclass
class Token:
    """OAuth token set obtained from a successful auth flow.

    Tokens are captured after a clean SUCCESS result (no MFA) via MSAL's
    ROPC (Resource Owner Password Credential) flow. Additional tokens may
    be minted through FOCI refresh token exchange.

    Attributes:
        username: The user these tokens belong to.
        access_token: Bearer token for API access.
        refresh_token: Long-lived token for minting new access tokens.
            This is the key to FOCI exchange.
        id_token: JWT containing user identity claims.
        client_id: The OAuth client ID used to obtain this token.
        resource: The resource/audience URL the token grants access to.
        expires_at: When the access token expires (UTC), or ``None`` if unknown.
        is_foci: Whether this token was obtained via FOCI exchange (vs. direct auth).
    """

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
    """Result from a user enumeration check.

    Each record represents a single username tested against one
    enumeration method. Stored in the ``enum_results`` table.

    Attributes:
        username: The email address that was tested.
        method: Enumeration method used ("onedrive", "teams", "msol", "login").
        exists: Whether the user was confirmed to exist in the tenant.
        timestamp: When the check was performed (UTC).
    """

    username: str
    method: str
    exists: bool
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class LockedAccount:
    """Tracks an account that has been locked during spraying.

    Created when a spray attempt returns ``ACCOUNT_LOCKED`` (AADSTS50053).
    Used by the spray engine to skip locked accounts and by the lockout
    threshold to decide when to abort the spray entirely.

    Attributes:
        username: The locked account's email address.
        locked_at: When the lockout was detected (UTC).
        attempt_count: Number of attempts made against this account before lockout.
    """

    username: str
    locked_at: datetime = field(default_factory=_utcnow)
    attempt_count: int = 0
