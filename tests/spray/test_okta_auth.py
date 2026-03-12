"""Tests for Okta authenticator module."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from cloudspray.constants.error_codes import AuthResult
from cloudspray.spray.okta_auth import OktaAuthenticator
from cloudspray.state.models import SprayAttempt


class TestOktaClassifyResponse:
    """Verify _classify_response maps Okta API responses to AuthResult."""

    def _auth(self):
        return OktaAuthenticator("corp.okta.com")

    def test_success(self):
        result = self._auth()._classify_response(200, {"status": "SUCCESS"})
        assert result == AuthResult.SUCCESS

    def test_mfa_required(self):
        result = self._auth()._classify_response(200, {"status": "MFA_REQUIRED"})
        assert result == AuthResult.VALID_PASSWORD_MFA_REQUIRED

    def test_mfa_enroll(self):
        result = self._auth()._classify_response(200, {"status": "MFA_ENROLL"})
        assert result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT

    def test_locked_out(self):
        result = self._auth()._classify_response(200, {"status": "LOCKED_OUT"})
        assert result == AuthResult.ACCOUNT_LOCKED

    def test_password_expired(self):
        result = self._auth()._classify_response(200, {"status": "PASSWORD_EXPIRED"})
        assert result == AuthResult.VALID_PASSWORD_EXPIRED

    def test_invalid_password_401(self):
        result = self._auth()._classify_response(401, {"errorCode": "E0000004"})
        assert result == AuthResult.INVALID_PASSWORD

    def test_rate_limited_429(self):
        result = self._auth()._classify_response(429, {"errorCode": "E0000047"})
        assert result == AuthResult.RATE_LIMITED

    def test_unknown_status_200(self):
        result = self._auth()._classify_response(200, {"status": "SOME_NEW_STATUS"})
        assert result == AuthResult.UNKNOWN_ERROR

    def test_server_error_500(self):
        result = self._auth()._classify_response(500, {})
        assert result == AuthResult.UNKNOWN_ERROR


class TestOktaAttempt:
    """Verify full attempt() method returns correct SprayAttempt."""

    @patch("cloudspray.spray.okta_auth.random.choice", return_value="FakeUA/1.0")
    def test_attempt_success(self, mock_choice):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "SUCCESS"}
        mock_resp.status_code = 200
        mock_session.post.return_value = mock_resp

        auth = OktaAuthenticator("corp.okta.com", proxy_session=mock_session)
        attempt = auth.attempt("user@corp.com", "Password123")

        assert isinstance(attempt, SprayAttempt)
        assert attempt.username == "user@corp.com"
        assert attempt.password == "Password123"
        assert attempt.result == AuthResult.SUCCESS
        assert attempt.endpoint == "https://corp.okta.com/api/v1/authn"
        assert attempt.client_id == "okta-signin-widget"

        mock_session.post.assert_called_once()
        call_kwargs = mock_session.post.call_args
        assert call_kwargs[1]["json"] == {
            "username": "user@corp.com",
            "password": "Password123",
        }

    @patch("cloudspray.spray.okta_auth.random.choice", return_value="FakeUA/1.0")
    def test_attempt_invalid_password(self, mock_choice):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"errorCode": "E0000004"}
        mock_resp.status_code = 401
        mock_session.post.return_value = mock_resp

        auth = OktaAuthenticator("corp.okta.com", proxy_session=mock_session)
        attempt = auth.attempt("user@corp.com", "wrong")

        assert attempt.result == AuthResult.INVALID_PASSWORD
        assert attempt.error_code == "E0000004"
