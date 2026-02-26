"""Microsoft Teams external search enumeration.

Requires a sacrificial M365 account to authenticate against the Teams API.
Uses the Teams user search endpoint to determine if target users exist.
"""

import random
import time

import msal
import requests

from cloudspray.constants import USER_AGENTS
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.state.models import EnumResult

METHOD_NAME = "teams"

# Microsoft Teams first-party client ID
TEAMS_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

# Teams Skype API scope for token acquisition
TEAMS_SCOPE = ["https://api.spaces.skype.com/.default"]

# Teams user search endpoint
TEAMS_SEARCH_URL = (
    "https://teams.microsoft.com/api/mt/part/emea-02/beta/users/searchV2"
)


class TeamsEnumerator:
    """Enumerate users via Microsoft Teams external search API.

    Requires a sacrificial account (valid M365 credentials).
    Uses the Teams user search endpoint to look up target accounts.

    Response interpretation:
    - 200 with user data in response = user exists
    - 200 with empty results = user does not exist
    - 403 = external access blocked (method won't work for this tenant)
    """

    def __init__(
        self,
        domain: str,
        db: StateDB,
        reporter: ConsoleReporter,
        auth_user: str,
        auth_pass: str,
        proxy_session: requests.Session | None = None,
    ):
        self._domain = domain
        self._db = db
        self._reporter = reporter
        self._auth_user = auth_user
        self._auth_pass = auth_pass
        self._session = proxy_session or requests.Session()
        self._access_token: str | None = None

    def _authenticate(self) -> bool:
        """Authenticate the sacrificial account and obtain a Teams token.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        auth_domain = self._auth_user.split("@")[1] if "@" in self._auth_user else self._domain
        authority = f"https://login.microsoftonline.com/{auth_domain}"

        app = msal.PublicClientApplication(
            TEAMS_CLIENT_ID,
            authority=authority,
            http_client=self._session,
        )

        result = app.acquire_token_by_username_password(
            self._auth_user,
            self._auth_pass,
            scopes=TEAMS_SCOPE,
        )

        if result and "access_token" in result:
            self._access_token = result["access_token"]
            return True

        error_desc = result.get("error_description", "unknown error") if result else "no response"
        self._reporter.error(f"Teams auth failed for sacrificial account: {error_desc}")
        return False

    def _search_user(self, email: str) -> bool | None:
        """Search for a single user via the Teams API.

        Returns:
            True if user exists, False if not found, None if lookup was ambiguous.
        """
        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "User-Agent": random.choice(USER_AGENTS),
        }

        payload = {
            "searchQuery": email,
            "searchFilters": "People",
        }

        try:
            response = self._session.post(
                TEAMS_SEARCH_URL,
                json=payload,
                headers=headers,
                timeout=15,
            )
        except requests.RequestException as exc:
            self._reporter.debug(f"Teams search request failed for {email}: {exc}")
            return None

        if response.status_code == 403:
            self._reporter.error(
                "External access blocked by tenant policy. Teams enumeration unavailable."
            )
            return None

        if response.status_code != 200:
            self._reporter.debug(
                f"Unexpected status {response.status_code} for {email}"
            )
            return None

        try:
            data = response.json()
        except ValueError:
            self._reporter.debug(f"Invalid JSON in Teams response for {email}")
            return None

        # Check if the response contains user matches
        users = data.get("value", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            return True

        return False

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Probe Teams search for each user.

        Args:
            usernames: List of email addresses to check.

        Returns:
            List of confirmed existing users.
        """
        if not self._authenticate():
            self._reporter.error("Cannot proceed without valid Teams authentication.")
            return []

        self._reporter.info("Teams authentication successful, beginning enumeration.")
        confirmed: list[str] = []

        for username in usernames:
            email = username if "@" in username else f"{username}@{self._domain}"
            search_result = self._search_user(email)

            if search_result is None:
                # Ambiguous result
                exists = False
            else:
                exists = search_result

            if exists:
                confirmed.append(email)

            result = EnumResult(username=email, method=METHOD_NAME, exists=exists)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, exists, METHOD_NAME)

            time.sleep(random.uniform(0.5, 2.0))

        return confirmed
