"""Microsoft Teams external search enumeration.

Requires a sacrificial M365 account to authenticate against the Teams API.
Uses the Teams user search endpoint to determine if target users exist.

How it works:
    Microsoft Teams allows users to search for people outside their own
    organization (external/federated search) unless the target tenant has
    explicitly disabled this. By authenticating with a *sacrificial* M365
    account (one the tester controls, not in the target tenant) and searching
    for target email addresses, we can determine which accounts are real:

    1. Authenticate the sacrificial account via MSAL's ROPC flow to obtain a
       bearer token scoped to the Teams/Skype API.
    2. For each candidate email, POST a search request to the Teams user-search
       endpoint (``/api/mt/part/{region}/beta/users/searchV2``).
    3. If the response contains user data in its results array, the account
       exists. An empty results array means the account was not found.
    4. A 403 response indicates the target tenant blocks external lookups
       entirely, at which point enumeration is aborted.

    The search endpoint is region-specific. Common region slugs include
    ``amer-01``, ``apac-01``, and ``emea-02``. The default is ``emea-02`` but
    this can be overridden at construction time.

Why this technique is useful:
    Teams enumeration is moderately stealthy. The search calls do not generate
    sign-in log entries for the *target* users -- only the sacrificial account's
    authentication appears in its own tenant logs. However, the technique
    requires valid credentials, and some organizations disable external search,
    making it unavailable against hardened tenants.

Dependencies:
    - ``msal`` -- Microsoft Authentication Library, used for ROPC token
      acquisition with the sacrificial account.
    - ``cloudspray.constants.USER_AGENTS`` -- rotated User-Agent strings.
    - ``cloudspray.state.db.StateDB`` -- result persistence.
    - ``cloudspray.reporting.console.ConsoleReporter`` -- live terminal output.
"""

import random
import re
import time

import msal
import requests

from cloudspray.constants import USER_AGENTS
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.state.models import EnumResult
from cloudspray.utils import normalize_email

METHOD_NAME = "teams"

# Microsoft Teams first-party client ID. This is the well-known application ID
# for the official Teams desktop/web client registered in Azure AD. Using it
# allows ROPC authentication the same way the real Teams app would.
TEAMS_CLIENT_ID = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"

# OAuth2 scope for the Teams/Skype backend API. The ``.default`` suffix
# requests all statically-configured permissions for this application.
TEAMS_SCOPE = ["https://api.spaces.skype.com/.default"]

# Teams user search endpoint pattern. The ``{region}`` placeholder must be
# replaced with the correct regional slug for the sacrificial account's home
# tenant. Common values: "amer-01" (Americas), "apac-01" (Asia-Pacific),
# "emea-02" (Europe/Middle East/Africa).
TEAMS_SEARCH_URL_TEMPLATE = (
    "https://teams.microsoft.com/api/mt/part/{region}/beta/users/searchV2"
)


class TeamsEnumerator:
    """Enumerate users via Microsoft Teams external search API.

    Requires a sacrificial M365 account (valid credentials controlled by the
    tester, *not* in the target tenant). The sacrificial account authenticates
    via ROPC to obtain a bearer token, then searches for each target email
    through the Teams people-search endpoint.

    Response interpretation:
        - 200 with user data in response -- user exists.
        - 200 with empty results -- user does not exist.
        - 403 -- the target tenant blocks external search; this technique
          will not work and enumeration is aborted immediately.

    Usage example::

        enumerator = TeamsEnumerator(
            "contoso.com", db, reporter,
            auth_user="sacrificial@tester.com",
            auth_pass="P@ssw0rd",
            region="amer-01",
        )
        valid = enumerator.enumerate(["john.smith", "jane.doe@contoso.com"])

    Args passed to ``__init__``:
        domain: Target tenant domain (e.g. ``contoso.com``).
        db: State database for persisting enumeration results.
        reporter: Console reporter for real-time output and debug messages.
        auth_user: Email address of the sacrificial M365 account.
        auth_pass: Password for the sacrificial account.
        proxy_session: Optional pre-configured ``requests.Session`` for IP
            rotation via Fireprox.
        region: Teams regional slug (default ``emea-02``). Must match the
            region where the sacrificial account's tenant is hosted.
    """

    def __init__(
        self,
        domain: str,
        db: StateDB,
        reporter: ConsoleReporter,
        auth_user: str,
        auth_pass: str,
        proxy_session: requests.Session | None = None,
        region: str = "emea-02",
    ):
        self._domain = domain
        self._db = db
        self._reporter = reporter
        self._auth_user = auth_user
        self._auth_pass = auth_pass
        self._session = proxy_session or requests.Session()
        self._access_token: str | None = None
        # Flag set to True if the target tenant returns 403, indicating
        # external search is blocked. Once set, enumeration stops early.
        self._access_blocked = False
        self._search_url = TEAMS_SEARCH_URL_TEMPLATE.format(region=region)

    def _authenticate(self) -> bool:
        """Authenticate the sacrificial account and obtain a Teams bearer token.

        Uses MSAL's Resource Owner Password Credential (ROPC) flow to exchange
        the sacrificial account's username/password for an access token scoped
        to the Teams/Skype API. The token is stored in ``self._access_token``
        for use by ``_search_user``.

        The MSAL authority URL is derived from the sacrificial account's domain
        (not the target domain), since authentication happens against the
        sacrificial account's own tenant.

        Returns:
            ``True`` if authentication succeeded and a token was obtained,
            ``False`` otherwise. On failure, the AADSTS error code is logged.
        """
        # Derive the Azure AD authority from the sacrificial account's domain,
        # not the target domain, since we authenticate against our own tenant.
        auth_domain = self._auth_user.split("@")[1] if "@" in self._auth_user else self._domain
        authority = f"https://login.microsoftonline.com/{auth_domain}"

        # PublicClientApplication is the correct MSAL app type for ROPC -- it
        # does not require a client secret.
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

        # Extract just the AADSTS error code (e.g. "AADSTS50126") from the
        # verbose error_description to keep console output clean.
        raw_desc = result.get("error_description", "unknown error") if result else "no response"
        code_match = re.search(r"AADSTS\d+", raw_desc)
        sanitized = code_match.group(0) if code_match else "authentication failed"
        self._reporter.error(f"Teams authentication failed: {sanitized}")
        return False

    def _search_user(self, email: str) -> bool | None:
        """Search for a single user via the Teams people-search API.

        Sends a POST request with the target email as the search query. The
        Teams API returns matching user objects if the account exists and is
        visible to external searchers.

        If a 403 is received, the ``_access_blocked`` flag is set to ``True``
        so that ``enumerate`` can abort early -- there is no point continuing
        if the tenant disallows external lookups.

        Args:
            email: Fully qualified email address to search for.

        Returns:
            ``True`` if the search returned at least one matching user,
            ``False`` if the results were empty (user not found), or ``None``
            if the response was ambiguous (network error, unexpected status
            code, or unparseable JSON).
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
                self._search_url,
                json=payload,
                headers=headers,
                timeout=15,
            )
        except requests.RequestException as exc:
            self._reporter.debug(f"Teams search request failed for {email}: {exc}")
            return None

        if response.status_code == 403:
            # 403 means the target tenant's policy blocks external user
            # lookups. This is a tenant-wide setting, so no further searches
            # will succeed -- set the flag to abort enumeration.
            self._access_blocked = True
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

        # The response shape can vary between API versions -- try both known
        # keys ("value" and "users") to find the results array.
        users = data.get("value", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            return True

        return False

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Authenticate the sacrificial account, then search for each user.

        The method first obtains a bearer token for the sacrificial account.
        If authentication fails (wrong credentials, MFA required, etc.), an
        empty list is returned immediately.

        During enumeration, if the target tenant returns a 403 on any search
        request, the loop aborts early because external search is disabled
        tenant-wide and subsequent requests would all fail.

        Ambiguous results (``None`` from ``_search_user``) are skipped and
        not persisted, similar to the MSOL enumerator's behavior.

        Args:
            usernames: Candidate email addresses (or bare usernames, which
                will be normalized to ``user@domain``).

        Returns:
            List of email addresses confirmed to exist via Teams search.

        Raises:
            No exceptions are raised; authentication and network errors are
            handled internally and reported through the console reporter.
        """
        if not self._authenticate():
            self._reporter.error("Cannot proceed without valid Teams authentication.")
            return []

        self._reporter.info("Teams authentication successful, beginning enumeration.")
        confirmed: list[str] = []
        # Deduplicate while preserving the caller's ordering.
        usernames = list(dict.fromkeys(usernames))

        for username in usernames:
            # Check the abort flag before each request -- once the tenant
            # blocks us, every subsequent search would also fail.
            if self._access_blocked:
                self._reporter.error("Stopping enumeration: tenant blocked external access.")
                break

            email = normalize_email(username, self._domain)
            search_result = self._search_user(email)

            if search_result is None:
                self._reporter.debug(f"Skipping ambiguous result for {email}")
                time.sleep(random.uniform(0.5, 2.0))
                continue

            if search_result:
                confirmed.append(email)

            result = EnumResult(username=email, method=METHOD_NAME, exists=search_result)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, search_result, METHOD_NAME)

            time.sleep(random.uniform(0.5, 2.0))

        return confirmed
