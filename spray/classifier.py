"""Azure AD authentication response classifier.

When MSAL's ``acquire_token_by_username_password`` completes, it returns
either a dict with an ``access_token`` key (success) or a dict with an
``error_description`` containing an AADSTS error code (failure). This module
extracts that code and maps it to a semantic ``AuthResult`` enum value.

**How AADSTS error codes work:**
Azure AD encodes the reason for every authentication failure as an "AADSTS"
code embedded in the error description string. The format is
``AADSTS<numeric_code>``, for example:

- ``AADSTS50126`` -- Invalid password (wrong credentials).
- ``AADSTS50076`` -- MFA is required, meaning the password was correct but a
  second factor is needed. This is a "valid password" signal for spraying.
- ``AADSTS50053`` -- Account is locked due to too many failed sign-in
  attempts. This triggers the engine's lockout-detection logic.
- ``AADSTS50079`` -- MFA enrollment required. The password is valid and the
  user has no MFA method registered yet -- a high-value finding during a
  pentest because an attacker could register their own MFA device.
- ``AADSTS53003`` -- Conditional Access policy blocked the sign-in. Password
  is valid but a policy (IP restriction, device compliance, etc.) prevents
  token issuance.
- ``AADSTS50055`` -- Password is expired. Valid credentials but the user must
  change their password before signing in.

The full mapping lives in :data:`cloudspray.constants.error_codes.AADSTS_MAP`.
Codes not present in the map fall through to ``AuthResult.UNKNOWN_ERROR``.
"""

import re

from cloudspray.constants.error_codes import AADSTS_MAP, AuthResult

# Regex to extract the numeric portion of an AADSTS error code from MSAL's
# error_description string. Azure AD always formats these as "AADSTS" followed
# by digits, e.g., "AADSTS50126: Invalid username or password."
_AADSTS_PATTERN = re.compile(r"AADSTS(\d+)")


def classify_auth_result(
    result: dict | None, error: Exception | None = None
) -> tuple[AuthResult, str]:
    """Classify an MSAL authentication response into a semantic AuthResult.

    This function is the single point of truth for interpreting what happened
    during an authentication attempt. The spray engine uses the returned
    ``AuthResult`` to decide whether to record a valid credential, track a
    lockout, back off for rate limiting, or simply move on.

    The classification priority is:
    1. If an exception was raised (network error, MSAL bug), return UNKNOWN_ERROR.
    2. If the result is ``None`` (should not happen normally), return UNKNOWN_ERROR.
    3. If the result contains an ``access_token``, the password is correct and
       no MFA/CA policy blocked issuance -- return SUCCESS.
    4. Otherwise, extract the AADSTS code from ``error_description`` and look
       it up in ``AADSTS_MAP``. Return the mapped AuthResult or UNKNOWN_ERROR
       if the code is unrecognized.

    Args:
        result: The dict returned by MSAL's
            ``acquire_token_by_username_password()``. Contains either an
            ``access_token`` key on success, or ``error``/``error_description``
            keys on failure.
        error: Any exception raised during the MSAL call (e.g., network
            timeout, connection refused). ``None`` if the call completed
            without throwing.

    Returns:
        A tuple of ``(AuthResult, error_code)`` where ``error_code`` is the
        numeric AADSTS code as a string (e.g., ``"50126"``) or an empty
        string if no code was extracted.
    """
    # Exception during the HTTP call itself -- network issue, proxy failure, etc.
    if error is not None:
        return AuthResult.UNKNOWN_ERROR, str(error)

    # Defensive guard: MSAL should always return a dict, but handle None.
    if result is None:
        return AuthResult.UNKNOWN_ERROR, ""

    # A successful authentication returns an access_token directly.
    if "access_token" in result:
        return AuthResult.SUCCESS, ""

    # Extract the AADSTS error code from the human-readable error_description.
    error_description = result.get("error_description", "")
    match = _AADSTS_PATTERN.search(error_description)
    if not match:
        return AuthResult.UNKNOWN_ERROR, ""

    # Look up the numeric code in our classification map.
    code = match.group(1)
    mapped_result = AADSTS_MAP.get(code, AuthResult.UNKNOWN_ERROR)
    return mapped_result, code
