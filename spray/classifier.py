import re

from cloudspray.constants.error_codes import AADSTS_MAP, AuthResult

_AADSTS_PATTERN = re.compile(r"AADSTS(\d+)")


def classify_auth_result(
    result: dict | None, error: Exception | None = None
) -> tuple[AuthResult, str]:
    """Classify an MSAL authentication result into an AuthResult enum value.

    Args:
        result: The result dict from MSAL's acquire_token_by_username_password().
        error: Any exception raised during the auth call.

    Returns:
        Tuple of (AuthResult, error_code_string_or_empty).
    """
    if error is not None:
        return AuthResult.UNKNOWN_ERROR, str(error)

    if result is None:
        return AuthResult.UNKNOWN_ERROR, ""

    if "access_token" in result:
        return AuthResult.SUCCESS, ""

    error_description = result.get("error_description", "")
    match = _AADSTS_PATTERN.search(error_description)
    if not match:
        return AuthResult.UNKNOWN_ERROR, ""

    code = match.group(1)
    mapped_result = AADSTS_MAP.get(code, AuthResult.UNKNOWN_ERROR)
    return mapped_result, code
