"""Tests for AADSTS error code classification."""
from cloudspray.spray.classifier import classify_auth_result
from cloudspray.constants.error_codes import AuthResult


def test_success_with_access_token():
    result, code = classify_auth_result({"access_token": "eyJ..."})
    assert result == AuthResult.SUCCESS
    assert code == ""


def test_mfa_required_50076():
    result, code = classify_auth_result({
        "error": "interaction_required",
        "error_description": "AADSTS50076: Due to a configuration change",
    })
    assert result == AuthResult.VALID_PASSWORD_MFA_REQUIRED
    assert code == "50076"


def test_invalid_password_50126():
    result, code = classify_auth_result({
        "error": "invalid_grant",
        "error_description": "AADSTS50126: Error validating credentials",
    })
    assert result == AuthResult.INVALID_PASSWORD
    assert code == "50126"


def test_user_not_found_50034():
    result, code = classify_auth_result({
        "error": "invalid_grant",
        "error_description": "AADSTS50034: The user account does not exist",
    })
    assert result == AuthResult.USER_NOT_FOUND
    assert code == "50034"


def test_account_locked_50053():
    result, code = classify_auth_result({
        "error": "invalid_grant",
        "error_description": "AADSTS50053: The account is locked",
    })
    assert result == AuthResult.ACCOUNT_LOCKED
    assert code == "50053"


def test_unknown_error_code():
    result, code = classify_auth_result({
        "error": "some_error",
        "error_description": "AADSTS99999: Something unknown happened",
    })
    assert result == AuthResult.UNKNOWN_ERROR
    assert code == "99999"


def test_no_error_no_token():
    """Response with neither access_token nor error."""
    result, code = classify_auth_result({})
    assert result == AuthResult.UNKNOWN_ERROR


def test_none_result():
    """None result returns UNKNOWN_ERROR."""
    result, code = classify_auth_result(None)
    assert result == AuthResult.UNKNOWN_ERROR
    assert code == ""


def test_exception_passed():
    """When an exception is passed, returns UNKNOWN_ERROR with error string."""
    exc = ConnectionError("timeout")
    result, code = classify_auth_result({}, error=exc)
    assert result == AuthResult.UNKNOWN_ERROR
    assert code == "timeout"
