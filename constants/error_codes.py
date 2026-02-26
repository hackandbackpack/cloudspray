from enum import Enum


class AuthResult(Enum):
    """Possible outcomes from an authentication attempt against Azure AD."""

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


# Maps AADSTS error code strings to their AuthResult classification.
# Multiple codes can map to the same result (e.g. several MFA-related codes).
AADSTS_MAP: dict[str, AuthResult] = {
    # Valid password but MFA is enforced
    "50076": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50074": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50158": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50072": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "50173": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    # Valid password, user needs to enroll in MFA — attacker can register
    "50079": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    "53004": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    # Valid password but conditional access policy blocks sign-in
    "53003": AuthResult.VALID_PASSWORD_CA_BLOCKED,
    "530034": AuthResult.VALID_PASSWORD_CA_BLOCKED,
    # Valid password but it has expired
    "50055": AuthResult.VALID_PASSWORD_EXPIRED,
    # Wrong password
    "50126": AuthResult.INVALID_PASSWORD,
    # Account is locked out (too many failed attempts)
    "50053": AuthResult.ACCOUNT_LOCKED,
    # Account exists but is disabled
    "50057": AuthResult.ACCOUNT_DISABLED,
    # Username does not exist in the tenant
    "50034": AuthResult.USER_NOT_FOUND,
    # Tenant does not exist or is misconfigured
    "50128": AuthResult.TENANT_NOT_FOUND,
    "50059": AuthResult.TENANT_NOT_FOUND,
    # Throttled by Azure AD
    "50196": AuthResult.RATE_LIMITED,
}
