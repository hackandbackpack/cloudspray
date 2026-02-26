"""OneDrive URL probing for user enumeration.

Passive technique that checks whether a user's OneDrive personal site exists
by probing the expected SharePoint URL. No authentication required.
"""

import random
import time

import requests

from cloudspray.constants import USER_AGENTS
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.state.models import EnumResult
from cloudspray.utils import normalize_email

METHOD_NAME = "onedrive"


class OneDriveEnumerator:
    """Enumerate users via OneDrive personal site URLs.

    Probes https://{tenant}-my.sharepoint.com/personal/{user_formatted}_{domain_formatted}/
    where user_formatted = username with dots/@ replaced by underscores,
    domain_formatted = domain with dots replaced by underscores.

    Response interpretation:
    - 403 Forbidden = user exists (site exists but access denied)
    - 404 Not Found = user does not exist
    - 401 Unauthorized = ambiguous (may or may not exist)
    """

    def __init__(
        self,
        domain: str,
        db: StateDB,
        reporter: ConsoleReporter,
        proxy_session: requests.Session | None = None,
    ):
        self._domain = domain
        self._tenant = domain.split(".")[0]
        self._db = db
        self._reporter = reporter
        self._session = proxy_session or requests.Session()

    def _format_username(self, email: str) -> str:
        """Convert user@domain.com to user_domain_com for URL construction."""
        return email.replace("@", "_").replace(".", "_")

    def _build_url(self, email: str) -> str:
        """Build the OneDrive personal site URL for a given email address."""
        formatted = self._format_username(email)
        return (
            f"https://{self._tenant}-my.sharepoint.com"
            f"/personal/{formatted}/"
        )

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Probe OneDrive URLs for each user.

        Args:
            usernames: List of email addresses to check.

        Returns:
            List of confirmed existing users.
        """
        confirmed: list[str] = []
        usernames = list(dict.fromkeys(usernames))  # preserve order, remove dupes

        for username in usernames:
            email = normalize_email(username, self._domain)
            url = self._build_url(email)
            exists = False

            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                response = self._session.head(url, timeout=10, allow_redirects=True, headers=headers)
                status = response.status_code

                if status == 403:
                    exists = True
                    confirmed.append(email)
                elif status == 404:
                    exists = False
                else:
                    # 401 or other codes are ambiguous, treat as not confirmed
                    self._reporter.debug(
                        f"Ambiguous response for {email}: HTTP {status}"
                    )
                    exists = False

            except requests.RequestException as exc:
                self._reporter.debug(f"Request failed for {email}: {exc}")
                exists = False

            result = EnumResult(username=email, method=METHOD_NAME, exists=exists)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, exists, METHOD_NAME)

            # Small random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 2.0))

        return confirmed
