"""Tests for SprayEngine lockout handling, circuit breaker, and accounting.

These cover the retry path specifically. It previously ran through a second,
trimmed-down copy of the main loop that had lost the circuit breaker and the
rate-limit re-queue, so retried pairs were sprayed with no safety mechanisms.
"""

from datetime import datetime, timedelta, timezone

from cloudspray.constants.error_codes import AuthResult
from cloudspray.spray.engine import (
    MAX_COOLDOWN_WAIT_SECONDS,
    MAX_LOCKOUT_DEFERRALS,
    SprayEngine,
)


class FakeSprayConfig:
    def __init__(self, lockout_threshold=10, lockout_cooldown=1800):
        self.delay = 0
        self.jitter = 0
        self.shuffle_mode = "standard"
        self.lockout_threshold = lockout_threshold
        self.lockout_cooldown = lockout_cooldown


class FakeConfig:
    def __init__(self, **kwargs):
        self.spray = FakeSprayConfig(**kwargs)


class FakeAttempt:
    def __init__(self, username, password, result):
        self.username = username
        self.password = password
        self.result = result
        self.timestamp = datetime.now(timezone.utc)


class FakeAuthenticator:
    """Returns a scripted result per username, recording every attempt made."""

    def __init__(self, results: dict[str, AuthResult], default=AuthResult.INVALID_PASSWORD):
        self._results = results
        self._default = default
        self.attempts: list[tuple[str, str]] = []

    def attempt(self, username, password):
        self.attempts.append((username, password))
        result = self._results.get(username, self._default)
        # A scripted list lets a user lock once then behave differently later.
        if isinstance(result, list):
            result = result.pop(0) if result else self._default
        return FakeAttempt(username, password, result)


class FakeDB:
    def __init__(self):
        self.recorded: list[tuple[str, str]] = []
        self.locked: list[str] = []

    def filter_unattempted_pairs(self, pairs):
        return pairs

    def get_valid_credentials(self):
        return []

    def record_attempt(self, attempt):
        self.recorded.append((attempt.username, attempt.password))

    def record_valid_credential(self, cred):
        pass

    def record_locked_account(self, locked):
        self.locked.append(locked.username)


class FakeProgress:
    def __init__(self):
        self.total = None

    def update(self, task_id, total=None, **kwargs):
        if total is not None:
            self.total = total

    def stop(self):
        pass


class FakeReporter:
    def __init__(self):
        self.progress = FakeProgress()
        self.messages: list[tuple[str, str]] = []

    def start_spray(self, total):
        self.progress.total = total
        return self.progress, "task"

    def update_progress(self, progress, task_id, advance=1):
        pass

    def print_result(self, attempt):
        pass

    def summary_table(self, creds):
        pass

    def lockout_warning(self, count):
        self.messages.append(("lockout_warning", str(count)))

    def info(self, message):
        self.messages.append(("info", message))

    def warning(self, message):
        self.messages.append(("warning", message))

    def error(self, message):
        self.messages.append(("error", message))

    def text(self) -> str:
        return " | ".join(m for _, m in self.messages)


def build(results=None, threshold=10, cooldown=1800, default=AuthResult.INVALID_PASSWORD):
    auth = FakeAuthenticator(results or {}, default=default)
    db = FakeDB()
    reporter = FakeReporter()
    engine = SprayEngine(
        FakeConfig(lockout_threshold=threshold, lockout_cooldown=cooldown),
        db,
        auth,
        reporter,
    )
    return engine, auth, db, reporter


class TestCircuitBreaker:
    def test_trips_after_consecutive_lockouts(self) -> None:
        users = [f"u{i}@example.com" for i in range(10)]
        engine, auth, db, reporter = build(
            threshold=3, default=AuthResult.ACCOUNT_LOCKED
        )
        engine.run(users, ["Password1"], resume=False)

        # Stops at the threshold instead of walking the whole list.
        assert len(auth.attempts) == 3
        assert any(kind == "lockout_warning" for kind, _ in reporter.messages)

    def test_non_lockout_result_resets_counter(self) -> None:
        """Checked directly, since both shuffle modes randomize spray order and
        a run of lockouts can otherwise trip the breaker by luck of the draw."""
        engine, _, _, _ = build(threshold=3)

        engine._handle_result(
            FakeAttempt("a@example.com", "P1", AuthResult.ACCOUNT_LOCKED)
        )
        engine._handle_result(
            FakeAttempt("b@example.com", "P1", AuthResult.ACCOUNT_LOCKED)
        )
        assert engine._consecutive_lockouts == 2

        engine._handle_result(
            FakeAttempt("c@example.com", "P1", AuthResult.INVALID_PASSWORD)
        )
        assert engine._consecutive_lockouts == 0

    def test_valid_password_also_resets_counter(self) -> None:
        engine, _, _, _ = build(threshold=3)
        engine._handle_result(
            FakeAttempt("a@example.com", "P1", AuthResult.ACCOUNT_LOCKED)
        )
        engine._handle_result(FakeAttempt("b@example.com", "P1", AuthResult.SUCCESS))
        assert engine._consecutive_lockouts == 0

    def test_lockout_increments_and_does_not_self_reset(self) -> None:
        """The lockout branch must return before the trailing reset, or the
        circuit breaker could never accumulate a count at all."""
        engine, _, _, _ = build(threshold=3)
        for name in ("a", "b", "c"):
            engine._handle_result(
                FakeAttempt(f"{name}@example.com", "P1", AuthResult.ACCOUNT_LOCKED)
            )
        assert engine._consecutive_lockouts == 3

    def test_breaker_applies_during_lockout_retry(self) -> None:
        """The retry phase used to have no breaker at all."""
        users = [f"u{i}@example.com" for i in range(6)]
        engine, auth, db, reporter = build(
            threshold=4, cooldown=0, default=AuthResult.ACCOUNT_LOCKED
        )
        engine.run(users, ["Password1"], resume=False)

        # With a zero cooldown every user is instantly retryable, so without a
        # breaker in the retry path this would spray far past the threshold.
        assert len(auth.attempts) == 4


class TestLockoutDeferral:
    def test_locked_user_is_deferred_not_dropped(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": [AuthResult.ACCOUNT_LOCKED,
                                       AuthResult.INVALID_PASSWORD]},
            cooldown=0,
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        # First pair locks; the second is deferred and then retried once the
        # (zero-second) cooldown clears, rather than being silently discarded.
        assert len(auth.attempts) == 2

    def test_unattempted_pairs_are_reported(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.ACCOUNT_LOCKED}, cooldown=99999
        )
        engine.run(["a@example.com"], ["P1", "P2", "P3"], resume=False)

        # P1 locks the account; P2 and P3 can never run within the cooldown, so
        # the operator must be told they were not attempted.
        assert any(
            kind == "warning" and "NOT attempted" in message
            for kind, message in reporter.messages
        )
        assert "--resume" in reporter.text()

    def test_long_cooldown_does_not_block(self, monkeypatch) -> None:
        """Regression guard: waiting for the full cooldown hung the tool.

        A 99999s cooldown must never turn into a 99999s sleep.
        """
        slept: list[float] = []
        monkeypatch.setattr(
            "cloudspray.spray.engine.time.sleep", lambda s: slept.append(s)
        )
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.ACCOUNT_LOCKED}, cooldown=99999
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        assert all(s <= MAX_COOLDOWN_WAIT_SECONDS for s in slept)

    def test_short_cooldown_is_waited_out(self, monkeypatch) -> None:
        """A cooldown under the ceiling should produce a real wait request.

        Asserted on the requested sleep rather than on P2 being attempted:
        sleep is mocked here, so no wall-clock time actually passes and the
        account never really unlocks.
        """
        slept: list[float] = []
        monkeypatch.setattr(
            "cloudspray.spray.engine.time.sleep", lambda s: slept.append(s)
        )
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.ACCOUNT_LOCKED}, cooldown=30
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        cooldown_waits = [s for s in slept if s > 1.0]
        assert cooldown_waits, "expected a wait for the lockout cooldown"
        assert max(cooldown_waits) <= 30

    def test_waiting_is_bounded_and_never_spins(self, monkeypatch) -> None:
        """Regression guard: an unbounded wait loop with a sub-second remainder
        spun hundreds of times and burned ~30s of CPU."""
        slept: list[float] = []
        monkeypatch.setattr(
            "cloudspray.spray.engine.time.sleep", lambda s: slept.append(s)
        )
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.ACCOUNT_LOCKED}, cooldown=30
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        assert len(slept) <= MAX_LOCKOUT_DEFERRALS
        assert all(s >= 1.0 for s in slept)
        waiting_logs = [
            m for kind, m in reporter.messages if kind == "info" and "Waiting" in m
        ]
        assert len(waiting_logs) <= MAX_LOCKOUT_DEFERRALS
        assert not any("Waiting 0s" in m for m in waiting_logs)

    def test_deferral_is_bounded(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.ACCOUNT_LOCKED}, cooldown=0
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        # With a zero cooldown the pair is immediately retryable each round, so
        # only the deferral cap stops an endless lock/retry cycle.
        assert len(auth.attempts) <= 2 + MAX_LOCKOUT_DEFERRALS

    def test_is_locked_expires_after_cooldown(self) -> None:
        engine, _, _, _ = build(cooldown=60)
        engine._locked_users["a@example.com"] = datetime.now(timezone.utc) - timedelta(
            seconds=120
        )
        assert engine._is_locked("a@example.com") is False

    def test_is_locked_true_within_cooldown(self) -> None:
        engine, _, _, _ = build(cooldown=600)
        engine._locked_users["a@example.com"] = datetime.now(timezone.utc)
        assert engine._is_locked("a@example.com") is True


class TestRateLimitHandling:
    def test_rate_limited_pair_is_retried_not_lost(self, monkeypatch) -> None:
        monkeypatch.setattr("cloudspray.spray.engine.time.sleep", lambda _s: None)
        engine, auth, db, reporter = build(
            results={"a@example.com": [AuthResult.RATE_LIMITED,
                                       AuthResult.INVALID_PASSWORD]}
        )
        engine.run(["a@example.com"], ["P1"], resume=False)

        # Two attempts for one pair, and only the real result is persisted.
        assert len(auth.attempts) == 2
        assert db.recorded == [("a@example.com", "P1")]

    def test_rate_limited_during_retry_is_not_dropped(self, monkeypatch) -> None:
        """The retry phase silently discarded rate-limited pairs."""
        monkeypatch.setattr("cloudspray.spray.engine.time.sleep", lambda _s: None)
        engine, auth, db, reporter = build(
            results={
                "a@example.com": [AuthResult.ACCOUNT_LOCKED],
                "b@example.com": [AuthResult.RATE_LIMITED,
                                  AuthResult.INVALID_PASSWORD],
            },
            cooldown=0,
        )
        engine.run(["a@example.com", "b@example.com"], ["P1", "P2"], resume=False)

        # b's rate-limited pair must still end up recorded exactly once.
        b_recorded = [p for p in db.recorded if p[0] == "b@example.com"]
        assert len(b_recorded) == len(set(b_recorded))
        assert ("b@example.com", "P1") in db.recorded


class TestValidPasswordShortCircuit:
    def test_no_further_passwords_after_success(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.SUCCESS}
        )
        engine.run(["a@example.com"], ["P1", "P2", "P3"], resume=False)

        assert len(auth.attempts) == 1

    def test_progress_total_shrinks_only_for_dropped_pairs(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.SUCCESS}
        )
        engine.run(["a@example.com"], ["P1", "P2", "P3"], resume=False)

        # P2 and P3 will never be attempted once P1 succeeds, so the total
        # legitimately drops from 3 to 1.
        assert reporter.progress.total == 1

    def test_mfa_required_counts_as_valid_password(self) -> None:
        engine, auth, db, reporter = build(
            results={"a@example.com": AuthResult.VALID_PASSWORD_MFA_REQUIRED}
        )
        engine.run(["a@example.com"], ["P1", "P2"], resume=False)

        assert len(auth.attempts) == 1
