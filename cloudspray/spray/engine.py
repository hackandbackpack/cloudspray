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
from math import ceil

from cloudspray.settings import CloudSprayConfig
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

# How many times a pair may be deferred for lockout cooldown before it is given
# up on. Bounds the wait-retry-relock cycle for an account that keeps locking,
# which would otherwise loop for as long as the campaign runs.
MAX_LOCKOUT_DEFERRALS = 2

# Longest the engine will sit idle waiting for a lockout cooldown to expire.
# Waiting out a short cooldown saves a pointless re-run, but the cooldown
# defaults to 1800s and is operator-configurable, so blocking for the full
# window would hang the tool for half an hour with no output. Past this ceiling
# the run ends and reports exactly which pairs still need attempting, which is
# what --resume exists for.
MAX_COOLDOWN_WAIT_SECONDS = 120


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
        # Live count of pairs still expected to be attempted, used to keep the
        # progress total honest as pairs drop out of the workload.
        self._remaining = 0

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
            users: List of target UPNs (e.g., ``["user@example.com", ...]``).
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
            pairs = self._db.filter_unattempted_pairs(pairs)
            skipped = total_generated - len(pairs)
            if skipped:
                self._reporter.info(
                    f"Resuming: {skipped} already attempted, "
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
        self._remaining = remaining
        queue: deque[tuple[str, str]] = deque(pairs)
        # Pairs put off because their user is in lockout cooldown, with a count
        # of how many cooldown cycles each has already waited through.
        deferred: list[tuple[str, str]] = []
        deferral_counts: dict[tuple[str, str], int] = {}
        abandoned: list[tuple[str, str]] = []
        tripped = False
        wait_rounds = 0

        try:
            while queue or deferred:
                tripped = self._drain(
                    queue, deferred, deferral_counts, abandoned, progress, task_id
                )
                if tripped or not deferred:
                    break

                ready = [pair for pair in deferred if not self._is_locked(pair[0])]
                if ready:
                    deferred = [pair for pair in deferred if self._is_locked(pair[0])]
                    self._reporter.info(
                        f"{len({user for user, _ in ready})} user(s) out of lockout "
                        "cooldown, retrying"
                    )
                    queue.extend(ready)
                    continue

                # Everything left is still cooling down. Wait it out if that is
                # quick, otherwise stop and say what was left rather than either
                # dropping the work silently or hanging for the full window.
                wait = self._seconds_until_next_unlock(deferred)
                if not wait or wait > MAX_COOLDOWN_WAIT_SECONDS:
                    break

                # Bounded so a clock that does not advance as expected cannot
                # turn this into a spin loop.
                if wait_rounds >= MAX_LOCKOUT_DEFERRALS:
                    break
                wait_rounds += 1

                # Floored: a sub-second remainder would otherwise produce a
                # stream of near-zero sleeps and duplicate log lines.
                wait = max(1.0, wait)
                locked_names = sorted({user for user, _ in deferred})
                self._reporter.info(
                    f"All {len(deferred)} remaining pair(s) are in lockout cooldown. "
                    f"Waiting {ceil(wait)}s for the next account to clear "
                    f"({len(locked_names)} user(s): {', '.join(locked_names)})"
                )
                time.sleep(wait)
        finally:
            progress.stop()

        self._report_unfinished(abandoned, deferred, tripped)

        valid_creds = self._db.get_valid_credentials()
        self._reporter.summary_table(valid_creds)

    def _drain(
        self,
        queue: deque[tuple[str, str]],
        deferred: list[tuple[str, str]],
        deferral_counts: dict[tuple[str, str], int],
        abandoned: list[tuple[str, str]],
        progress,
        task_id,
    ) -> bool:
        """Process the queue until it empties or the circuit breaker trips.

        This is the single place a credential pair is ever attempted. Keeping it
        in one method is deliberate: the previous implementation had a second,
        trimmed-down copy of this loop for lockout retries that was missing the
        circuit breaker and the rate-limit re-queue, so the safety mechanisms
        silently did not apply to retried pairs.

        Args:
            queue: Pairs waiting to be attempted. Rate-limited pairs are pushed
                back onto it.
            deferred: Collects pairs whose user is in lockout cooldown.
            deferral_counts: Tracks how many times each pair has been deferred.
            abandoned: Collects pairs given up on after too many deferrals.
            progress: Live progress display.
            task_id: Progress task identifier.

        Returns:
            ``True`` if the circuit breaker tripped and the campaign must stop.
        """
        while queue:
            username, password = queue.popleft()
            pair = (username, password)

            # No point testing more passwords once we have a valid one.
            if username in self._confirmed_users:
                self._drop_pair(progress, task_id)
                continue

            if self._is_locked(username):
                count = deferral_counts.get(pair, 0) + 1
                deferral_counts[pair] = count
                if count > MAX_LOCKOUT_DEFERRALS:
                    abandoned.append(pair)
                    self._drop_pair(progress, task_id)
                else:
                    deferred.append(pair)
                continue

            # Block until the per-user delay window has elapsed.
            self._enforce_user_delay(username)

            attempt = self._auth.attempt(username, password)
            self._last_attempt_per_user[username] = attempt.timestamp
            self._reporter.print_result(attempt)

            self._handle_result(attempt)

            # Rate-limited attempts are not recorded (they did not produce a
            # real auth result) and are re-queued after a sleep.
            if attempt.result == AuthResult.RATE_LIMITED:
                self._reporter.info(
                    f"Rate limited on {attempt.username}, "
                    f"sleeping {RATE_LIMIT_SLEEP_SECONDS}s then retrying..."
                )
                time.sleep(RATE_LIMIT_SLEEP_SECONDS)
                queue.append(pair)
            else:
                self._db.record_attempt(attempt)
                self._reporter.update_progress(progress, task_id)

            # Circuit breaker: too many consecutive lockouts means the spray is
            # causing damage and must stop immediately.
            if self._consecutive_lockouts >= self._config.spray.lockout_threshold:
                self._reporter.lockout_warning(self._consecutive_lockouts)
                self._reporter.error(
                    f"{self._consecutive_lockouts} consecutive lockouts — "
                    "stopping spray to protect accounts."
                )
                return True

        return False

    def _drop_pair(self, progress, task_id) -> None:
        """Shrink the progress total for a pair that left the workload for good.

        Only called for pairs that will never be attempted (user already
        confirmed, or abandoned after repeated lockouts). Deferred pairs keep
        their slot in the total, since they are postponed rather than dropped.
        """
        self._remaining -= 1
        progress.update(task_id, total=self._remaining)

    def _seconds_until_next_unlock(
        self, pairs: list[tuple[str, str]]
    ) -> float | None:
        """Seconds until the earliest still-locked user among pairs clears.

        Args:
            pairs: Pairs currently deferred for lockout cooldown.

        Returns:
            Seconds to wait, or ``None`` when nothing is actually locked.
        """
        cooldown = timedelta(seconds=self._config.spray.lockout_cooldown)
        now = datetime.now(timezone.utc)
        waits = []

        for username, _ in pairs:
            locked_at = self._locked_users.get(username)
            if locked_at is None:
                return None
            seconds_left = (locked_at + cooldown - now).total_seconds()
            if seconds_left <= 0:
                return None
            waits.append(seconds_left)

        return min(waits) if waits else None

    def _report_unfinished(
        self,
        abandoned: list[tuple[str, str]],
        deferred: list[tuple[str, str]],
        tripped: bool,
    ) -> None:
        """Account for every pair that was not attempted.

        Silence here is the real hazard: an operator who believes a user list
        was fully sprayed will not re-run it, and a locked or queued account
        that was never tested looks identical to one with no valid password.
        """
        if abandoned:
            names = sorted({user for user, _ in abandoned})
            self._reporter.warning(
                f"{len(abandoned)} pair(s) across {len(names)} user(s) were NOT "
                f"attempted: their accounts stayed locked through "
                f"{MAX_LOCKOUT_DEFERRALS} cooldown cycles ({', '.join(names)}). "
                "Re-run with --resume once those accounts unlock."
            )

        if deferred:
            names = sorted({user for user, _ in deferred})
            cause = (
                "when the circuit breaker stopped the spray"
                if tripped
                else "in lockout cooldown when the run ended"
            )
            self._reporter.warning(
                f"{len(deferred)} pair(s) across {len(names)} user(s) were NOT "
                f"attempted, still {cause} ({', '.join(names)}). Re-run with "
                "--resume to continue."
            )

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
