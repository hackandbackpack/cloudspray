"""Azure AD GetCredentialType enumeration.

Semi-passive technique that queries the GetCredentialType endpoint to determine
whether an email address corresponds to a valid Azure AD account. No authentication
required, but Microsoft applies aggressive rate limiting.
"""

import random
import time

import requests

from cloudspray.constants import USER_AGENTS
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.state.models import EnumResult

METHOD_NAME = "msol"

CREDENTIAL_TYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"


class MSOLEnumerator:
    """Enumerate users via Azure AD GetCredentialType endpoint.

    Semi-passive: no authentication required, but heavily rate-limited.
    Calls POST https://login.microsoftonline.com/common/GetCredentialType

    Response interpretation:
    - IfExistsResult == 0 = user exists
    - IfExistsResult == 1 = user does not exist
    - IfExistsResult == 5 or 6 = exists but in different tenant/realm
    - Other values or throttling = unknown
    """

    def __init__(
        self,
        domain: str,
        db: StateDB,
        reporter: ConsoleReporter,
        proxy_session: requests.Session | None = None,
    ):
        self._domain = domain
        self._db = db
        self._reporter = reporter
        self._session = proxy_session or requests.Session()

    def _build_request_body(self, email: str) -> dict:
        """Build the JSON payload for the GetCredentialType request."""
        return {
            "Username": email,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": "",
            "country": "US",
            "forceotclogin": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 0,
            "isSignup": False,
            "flowToken": "",
            "isAccessPassSupported": True,
        }

    def _check_user(self, email: str) -> bool | None:
        """Check a single user against the GetCredentialType endpoint.

        Returns:
            True if user exists, False if not found, None if ambiguous/throttled.
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
        }

        try:
            response = self._session.post(
                CREDENTIAL_TYPE_URL,
                json=self._build_request_body(email),
                headers=headers,
                timeout=10,
            )
        except requests.RequestException as exc:
            self._reporter.debug(f"Request failed for {email}: {exc}")
            return None

        if response.status_code != 200:
            self._reporter.debug(
                f"Non-200 response for {email}: HTTP {response.status_code}"
            )
            return None

        try:
            data = response.json()
        except ValueError:
            self._reporter.debug(f"Invalid JSON in response for {email}")
            return None

        if_exists = data.get("IfExistsResult")

        if if_exists == 0:
            return True
        if if_exists == 1:
            return False
        if if_exists in (5, 6):
            # User exists but in a different tenant/realm
            return True

        # Throttled or unrecognized value
        self._reporter.debug(
            f"Ambiguous IfExistsResult={if_exists} for {email}"
        )
        return None

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Probe GetCredentialType for each user.

        Args:
            usernames: List of email addresses to check.

        Returns:
            List of confirmed existing users.
        """
        confirmed: list[str] = []

        for username in usernames:
            email = username if "@" in username else f"{username}@{self._domain}"
            check_result = self._check_user(email)

            if check_result is None:
                exists = False
            else:
                exists = check_result

            if exists:
                confirmed.append(email)

            result = EnumResult(username=email, method=METHOD_NAME, exists=exists)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, exists, METHOD_NAME)

            # Longer delay due to rate limiting sensitivity
            time.sleep(random.uniform(1.0, 3.0))

        return confirmed
