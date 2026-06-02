"""Azure AD authentication error codes and result classification.

When Azure AD rejects an authentication attempt, it returns an error
response containing an ``AADSTS`` error code (e.g. ``AADSTS50126`` for
wrong password). CloudSpray extracts the numeric portion and looks it
up in ``AADSTS_MAP`` to classify the result.

The classification is critical because different error codes reveal
different things about the account:

- **INVALID_PASSWORD** (50126) -- The user exists but the password is wrong.
  This is the expected "miss" during spraying.
- **VALID_PASSWORD_MFA_REQUIRED** (50076, 50074, etc.) -- The password is
  correct but MFA blocks login. This is a confirmed credential!
- **VALID_PASSWORD_MFA_ENROLLMENT** (50079) -- Password correct and the user
  has not yet enrolled in MFA. This is the highest-value finding because
  an attacker can register their own MFA device.
- **VALID_PASSWORD_CA_BLOCKED** (53003) -- Password correct but a Conditional
  Access policy blocks the specific client/location. The CA probe module
  tests other client/endpoint combinations to find gaps.
- **ACCOUNT_LOCKED** (50053) -- Too many failed attempts. The spray engine
  uses this to enforce lockout safety thresholds.

The ``AuthResult`` enum is used throughout the codebase as the canonical
representation of an authentication outcome.
"""

from enum import Enum


class AuthResult(Enum):
    """Possible outcomes from an authentication attempt against Azure AD.

    Each value represents a classified result that determines how the spray
    engine, reporter, and post-exploitation modules handle the attempt.

    The ``VALID_PASSWORD_*`` variants all indicate the password is correct
    but some additional factor prevents a clean login.
    """

    SUCCESS = "success"
    VALID_PASSWORD_MFA_REQUIRED = "valid_password_mfa_required"
    VALID_PASSWORD_MFA_ENROLLMENT = "valid_password_mfa_enrollment"
    VALID_PASSWORD_CA_BLOCKED = "valid_password_ca_blocked"
    VALID_PASSWORD_EXPIRED = "valid_password_expired"
    INVALID_PASSWORD = "invalid_password"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    USER_NOT_FOUND = "user_not_found"
    TENANT_NOT_FOUND = "tenant_not_found"
    RATE_LIMITED = "rate_limited"
    UNKNOWN_ERROR = "unknown_error"


# Maps AADSTS error code strings (numeric portion only) to their AuthResult
# classification. The spray classifier extracts codes from Azure AD error
# responses and looks them up here. Multiple AADSTS codes can map to the
# same result (e.g. several codes all indicate MFA is required).
AADSTS_MAP: dict[str, AuthResult] = {
    # Valid password but MFA is enforced
    "50076": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50074": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50158": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50072": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50173": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    # Valid password, user needs to enroll in MFA -- attacker can register
    # their own device, making this the highest-value finding
    "50079": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    "53004": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    # Valid password but conditional access policy blocks sign-in
    # from the current client/location/device combination
    "53003": AuthResult.VALID_PASSWORD_CA_BLOCKED,
    "530034": AuthResult.VALID_PASSWORD_CA_BLOCKED,
    # Valid password but it has expired and must be reset
    "50055": AuthResult.VALID_PASSWORD_EXPIRED,
    # Wrong password -- the most common result during spraying
    "50126": AuthResult.INVALID_PASSWORD,
    # Account is locked out (too many failed attempts)
    "50053": AuthResult.ACCOUNT_LOCKED,
    # Account exists but is disabled by an administrator
    "50057": AuthResult.ACCOUNT_DISABLED,
    # Username does not exist in the tenant
    "50034": AuthResult.USER_NOT_FOUND,
    # Tenant does not exist or is misconfigured
    "50128": AuthResult.TENANT_NOT_FOUND,
    "50059": AuthResult.TENANT_NOT_FOUND,
    # Throttled by Azure AD rate limiting
    "50196": AuthResult.RATE_LIMITED,
}
