"""Password spray campaign orchestrator.

This module contains ``SprayEngine``, the central coordinator that drives the
entire spray campaign. It ties together the shuffler, authenticator, classifier,
state database, and console reporter into a single ``run()`` loop with several
safety mechanisms designed to prevent account lockouts during authorized
penetration tests.

**Safety mechanisms:**

1. **Per-user delay** -- A configurable minimum time gap (default 30s + random
   jitter) between consecutive attempts against the same user. This ensures
   that even in aggressive-shuffle mode, no single account sees rapid-fire
   failures that would trigger Azure AD's smart-lockout.

2. **Lockout cooldown** -- When an ``ACCOUNT_LOCKED`` response (AADSTS50053)
   is received, the user is placed in a cooldown period (default 30 minutes).
   Any queued pairs for that user are deferred and retried after the cooldown
   expires.

3. **Circuit breaker** -- If the engine detects N consecutive lockouts
   (configurable via ``lockout_threshold``, default 10), it halts the entire
   campaign immediately. This prevents a cascading lockout scenario where a
   widespread password policy change or aggressive smart-lockout setting
   could lock out every account in the target list.

4. **Rate-limit back-off** -- Azure AD throttling (AADSTS50196) triggers a
   60-second sleep, after which the same pair is re-queued for retry.

5. **Resume support** -- The engine queries the state database for previously
   attempted pairs and skips them, allowing a spray to be interrupted and
   resumed without repeating work or wasting attempts against lockout budgets.

6. **Confirmed-user skip** -- Once a valid password is found for a user, all
   remaining pairs for that user are skipped. There is no benefit to testing
   additional passwords, and it avoids unnecessary noise.
"""

import random
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from cloudspray.config import CloudSprayConfig
from cloudspray.constants.error_codes import AuthResult
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.spray.auth import Authenticator
from cloudspray.spray.shuffle import aggressive_shuffle, standard_shuffle
from cloudspray.state.db import StateDB
from cloudspray.state.models import LockedAccount, SprayAttempt, ValidCredential

# All AuthResult values that indicate the password was correct, even if the
# login was ultimately blocked by MFA, Conditional Access, or expiration.
# These are all "wins" from a pentest perspective -- the credential is valid.
_VALID_PASSWORD_RESULTS = {
    AuthResult.SUCCESS,
    AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    AuthResult.VALID_PASSWORD_CA_BLOCKED,
    AuthResult.VALID_PASSWORD_EXPIRED,
}

# How long to sleep when Azure AD returns a rate-limit (AADSTS50196) response.
RATE_LIMIT_SLEEP_SECONDS = 60


class SprayEngine:
    """Core password spray engine with per-user lockout cooldown and circuit breaker.

    The engine processes a queue of ``(username, password)`` pairs, sending each
    to the ``Authenticator`` and reacting to the classified result. It maintains
    three pieces of in-memory state:

    - ``_last_attempt_per_user``: Tracks when each user was last tested, used
      to enforce the per-user delay window.
    - ``_confirmed_users``: Users with a confirmed valid password, skipped for
      all subsequent pairs.
    - ``_locked_users``: Users that returned ``ACCOUNT_LOCKED``, mapped to the
      time they were locked. Pairs for these users are deferred to a retry
      queue and re-attempted after the cooldown period.

    The ``_consecutive_lockouts`` counter implements the circuit breaker: it
    increments on each lockout and resets on any non-lockout result. When it
    reaches the configured threshold, the campaign stops.

    Args:
        config: Loaded ``CloudSprayConfig`` with spray timing, shuffle mode,
            and lockout parameters.
        db: State database for persisting attempts, valid credentials, and
            locked accounts across runs.
        authenticator: ``Authenticator`` instance configured with the target
            domain and optional proxy session.
        reporter: Console reporter for live progress display and result output.
    """

    def __init__(
        self,
        config: CloudSprayConfig,
        db: StateDB,
        authenticator: Authenticator,
        reporter: ConsoleReporter,
    ):
        self._config = config
        self._db = db
        self._auth = authenticator
        self._reporter = reporter
        self._last_attempt_per_user: dict[str, datetime] = {}
        self._confirmed_users: set[str] = set()
        self._locked_users: dict[str, datetime] = {}
        self._consecutive_lockouts = 0

    def run(self, users: list[str], passwords: list[str], resume: bool = True) -> None:
        """Execute the full spray campaign.

        Builds credential pairs using the configured shuffle strategy, optionally
        filters out previously attempted pairs (resume mode), and processes each
        pair through the authenticator. Results are persisted to the state
        database in real time.

        The method is designed to be called once per campaign. It blocks until
        all pairs are processed, the circuit breaker trips, or an unhandled
        exception occurs (the progress display is stopped in a ``finally`` block
        regardless).

        Args:
            users: List of target UPNs (e.g., ``["user@contoso.com", ...]``).
            passwords: List of passwords to test, typically ordered by likelihood
                (e.g., seasonal passwords first).
            resume: If ``True`` (default), query the state database for pairs
                that were already attempted in a previous run and skip them.
                Set to ``False`` to retry all pairs from scratch.
        """
        if not users or not passwords:
            self._reporter.error("No users or passwords provided.")
            return

        pairs = self._build_pairs(users, passwords)
        total_generated = len(pairs)

        # Resume support: filter out pairs already recorded in the state DB
        # so interrupted campaigns can pick up where they left off.
        if resume:
            attempted = self._db.get_attempted_pairs()
            if attempted:
                pairs = [(u, p) for u, p in pairs if (u, p) not in attempted]
                self._reporter.info(
                    f"Resuming: {total_generated - len(pairs)} already attempted, "
                    f"{len(pairs)} remaining"
                )

        # Pre-load users that already have confirmed valid passwords from a
        # prior run so we skip them immediately.
        for cred in self._db.get_valid_credentials():
            self._confirmed_users.add(cred.username)

        remaining = len(pairs)
        self._reporter.info(
            f"Starting spray: {remaining} attempts "
            f"({len(users)} users x {len(passwords)} passwords)"
        )

        progress, task_id = self._reporter.start_spray(remaining)
        queue: deque[tuple[str, str]] = deque(pairs)
        # Pairs deferred because the user was in lockout cooldown. These are
        # retried after the main queue is exhausted and cooldowns have expired.
        skipped: list[tuple[str, str]] = []

        try:
            while queue:
                username, password = queue.popleft()

                # No point testing more passwords once we have a valid one.
                if username in self._confirmed_users:
                    self._reporter.update_progress(progress, task_id)
                    continue

                # Defer pairs for locked users -- they will be retried later.
                if self._is_locked(username):
                    skipped.append((username, password))
                    self._reporter.update_progress(progress, task_id)
                    continue

                # Block until the per-user delay window has elapsed.
                self._enforce_user_delay(username)

                attempt = self._auth.attempt(username, password)
                self._last_attempt_per_user[username] = attempt.timestamp
                self._reporter.print_result(attempt)

                self._handle_result(attempt)

                # Rate-limited attempts are not recorded (they did not produce
                # a real auth result) and are re-queued after a sleep.
                if attempt.result != AuthResult.RATE_LIMITED:
                    self._db.record_attempt(attempt)
                else:
                    self._reporter.info(
                        f"Rate limited on {attempt.username}, "
                        f"sleeping {RATE_LIMIT_SLEEP_SECONDS}s then retrying..."
                    )
                    time.sleep(RATE_LIMIT_SLEEP_SECONDS)
                    queue.append((attempt.username, attempt.password))

                self._reporter.update_progress(progress, task_id)

                # Circuit breaker: too many consecutive lockouts means the
                # spray is causing damage and must stop immediately.
                if self._consecutive_lockouts >= self._config.spray.lockout_threshold:
                    self._reporter.lockout_warning(self._consecutive_lockouts)
                    self._reporter.error(
                        f"{self._consecutive_lockouts} consecutive lockouts — "
                        "stopping spray to protect accounts."
                    )
                    break

            # Re-queue skipped users whose cooldown has expired
            if skipped and self._consecutive_lockouts < self._config.spray.lockout_threshold:
                ready = [(u, p) for u, p in skipped if not self._is_locked(u)]
                still_locked = [(u, p) for u, p in skipped if self._is_locked(u)]

                if ready:
                    self._reporter.info(
                        f"{len(ready)} previously locked user(s) ready for retry"
                    )
                    queue.extend(ready)

                if still_locked:
                    cooldown = self._config.spray.lockout_cooldown
                    locked_names = {u for u, _ in still_locked}
                    self._reporter.info(
                        f"{len(locked_names)} user(s) still in lockout cooldown "
                        f"({cooldown}s): {', '.join(sorted(locked_names))}"
                    )

                # Process the re-queued pairs that have exited cooldown.
                while queue:
                    username, password = queue.popleft()

                    if username in self._confirmed_users:
                        continue

                    if self._is_locked(username):
                        continue

                    self._enforce_user_delay(username)

                    attempt = self._auth.attempt(username, password)
                    self._last_attempt_per_user[username] = attempt.timestamp
                    self._reporter.print_result(attempt)

                    self._handle_result(attempt)

                    if attempt.result != AuthResult.RATE_LIMITED:
                        self._db.record_attempt(attempt)

        finally:
            progress.stop()

        valid_creds = self._db.get_valid_credentials()
        self._reporter.summary_table(valid_creds)

    def _build_pairs(
        self, users: list[str], passwords: list[str]
    ) -> list[tuple[str, str]]:
        """Generate credential pairs using the configured shuffle strategy.

        Delegates to either ``standard_shuffle`` (password-round ordering with
        randomized users) or ``aggressive_shuffle`` (fully random cartesian
        product) based on ``config.spray.shuffle_mode``.

        Args:
            users: Target UPN list.
            passwords: Password list.

        Returns:
            List of ``(username, password)`` tuples in spray order.
        """
        if self._config.spray.shuffle_mode == "aggressive":
            return aggressive_shuffle(users, passwords)
        return standard_shuffle(users, passwords)

    def _enforce_user_delay(self, username: str) -> None:
        """Sleep if necessary to respect the per-user delay window.

        Calculates how long ago the last attempt was made for this user and
        sleeps for the remaining time if the configured delay (plus a random
        jitter component) has not yet elapsed. The jitter adds randomness to
        the timing pattern, making the traffic less uniform and harder to
        fingerprint.

        Args:
            username: The UPN about to be tested.
        """
        last_time = self._last_attempt_per_user.get(username)
        if last_time is None:
            return

        delay = self._config.spray.delay
        # Add random jitter so attempts are not perfectly periodic.
        jitter = random.uniform(0, self._config.spray.jitter)
        required_gap = delay + jitter

        elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
        remaining_wait = required_gap - elapsed
        if remaining_wait > 0:
            time.sleep(remaining_wait)

    def _is_locked(self, username: str) -> bool:
        """Check if a user is currently in lockout cooldown.

        A user enters lockout cooldown when an ``ACCOUNT_LOCKED`` result is
        received. The user remains locked for ``config.spray.lockout_cooldown``
        seconds (default 1800 = 30 minutes). Once the cooldown expires, the
        user is removed from the locked set and becomes eligible for retry.

        Args:
            username: The UPN to check.

        Returns:
            ``True`` if the user is still within the cooldown window.
        """
        locked_at = self._locked_users.get(username)
        if locked_at is None:
            return False

        cooldown = timedelta(seconds=self._config.spray.lockout_cooldown)
        if datetime.now(timezone.utc) - locked_at >= cooldown:
            del self._locked_users[username]
            return False

        return True

    def _handle_result(self, attempt: SprayAttempt) -> None:
        """Process an authentication attempt result.

        Three categories of results are handled:

        1. **Valid password** (any result in ``_VALID_PASSWORD_RESULTS``):
           Record the credential in the state database, add the user to the
           confirmed set so no more passwords are tested, and reset the
           consecutive lockout counter.

        2. **Account locked** (``ACCOUNT_LOCKED``): Place the user in lockout
           cooldown, record the lockout event, and increment the consecutive
           lockout counter (feeding the circuit breaker).

        3. **Everything else** (invalid password, user not found, etc.):
           Reset the consecutive lockout counter. These are normal spray
           results that indicate the campaign is not causing lockouts.

        Args:
            attempt: The completed ``SprayAttempt`` with a classified result.
        """
        result = attempt.result

        if result in _VALID_PASSWORD_RESULTS:
            # Determine the specific MFA/blocking type for reporting.
            mfa_type = ""
            if result == AuthResult.VALID_PASSWORD_MFA_REQUIRED:
                mfa_type = "required"
            elif result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT:
                mfa_type = "enrollment"
            elif result == AuthResult.VALID_PASSWORD_CA_BLOCKED:
                mfa_type = "ca_blocked"
            elif result == AuthResult.VALID_PASSWORD_EXPIRED:
                mfa_type = "expired"

            cred = ValidCredential(
                username=attempt.username,
                password=attempt.password,
                result=result,
                mfa_type=mfa_type,
            )
            self._db.record_valid_credential(cred)
            self._confirmed_users.add(attempt.username)
            self._consecutive_lockouts = 0
            return

        if result == AuthResult.ACCOUNT_LOCKED:
            self._locked_users[attempt.username] = datetime.now(timezone.utc)
            locked = LockedAccount(username=attempt.username)
            self._db.record_locked_account(locked)
            self._consecutive_lockouts += 1
            return

        # Any non-lockout result resets the consecutive counter, proving
        # the spray is not causing widespread lockouts.
        self._consecutive_lockouts = 0
