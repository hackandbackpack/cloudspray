"""SQLite database layer for persisting spray state, results, and tokens.

This module implements ``StateDB``, the central persistence layer that records
every action CloudSpray takes. The database schema includes:

- **spray_attempts** -- One row per authentication attempt (user + password +
  client ID + endpoint + result). Used for resume support and audit trails.
- **valid_credentials** -- Confirmed working username/password pairs with their
  auth result type (SUCCESS, MFA_REQUIRED, etc.) and discovery timestamp.
- **tokens** -- OAuth tokens (access, refresh, id) captured from successful
  logins or FOCI exchanges.
- **enum_results** -- User existence checks from enumeration methods.
- **locked_accounts** -- Accounts detected as locked during spraying.
- **spray_metadata** -- Key/value store for session metadata (e.g. target domain).

All write operations use a thread-locked transaction context manager to ensure
atomicity and prevent corruption when multiple threads write concurrently.
The database uses SQLite WAL mode for better concurrent read performance.
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from cloudspray.constants.error_codes import AuthResult
from cloudspray.state.models import (
    EnumResult,
    LockedAccount,
    SprayAttempt,
    Token,
    ValidCredential,
)


class StateDB:
    """SQLite-backed state store for spray progress, results, and tokens.

    Thread-safe and supports resume by tracking every attempt made.
    Can be used as a context manager for automatic cleanup.

    Usage::

        with StateDB("cloudspray.db") as db:
            db.record_attempt(attempt)
            pairs = db.get_attempted_pairs()  # for resume
            creds = db.get_valid_credentials()

    The database file is created automatically if it does not exist.
    Tables are created on first connection via ``_create_tables()``.
    """

    def __init__(self, db_path: str | Path):
        """Open (or create) the SQLite database at *db_path*.

        Args:
            db_path: Filesystem path to the SQLite database file.
                Created automatically if it does not exist.
        """
        self._conn = sqlite3.connect(
            str(db_path),
            # Allow the connection to be used from any thread; we manage
            # thread safety ourselves via self._lock.
            check_same_thread=False,
        )
        # Use Row factory so columns can be accessed by name (row["username"])
        self._conn.row_factory = sqlite3.Row
        # WAL mode allows concurrent readers while a writer holds the lock
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._create_tables()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _create_tables(self) -> None:
        """Create all tables if they do not already exist.

        Called once during ``__init__``. Uses ``IF NOT EXISTS`` so it is
        safe to call on an already-initialized database (for resume).
        """
        with self._transaction() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS spray_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    result TEXT NOT NULL,
                    error_code TEXT DEFAULT '',
                    timestamp TEXT NOT NULL,
                    proxy_used TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS valid_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    result TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    mfa_type TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    id_token TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_foci INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enum_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    method TEXT NOT NULL,
                    exists_flag INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS locked_accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    locked_at TEXT NOT NULL,
                    attempt_count INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS spray_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

    @contextmanager
    def _transaction(self):
        """Acquire the thread lock, yield a cursor, and commit or rollback.

        All write operations go through this context manager. It ensures
        that only one thread writes at a time and that failed writes are
        rolled back cleanly.

        Yields:
            A ``sqlite3.Cursor`` for executing SQL statements.
        """
        with self._lock:
            cursor = self._conn.cursor()
            try:
                yield cursor
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # -- Recording methods --

    def record_attempt(self, attempt: SprayAttempt) -> None:
        """Persist a single spray attempt to the database.

        Every authentication attempt is recorded regardless of outcome.
        This provides the audit trail and enables resume support via
        :meth:`get_attempted_pairs`.

        Args:
            attempt: The spray attempt result to store.
        """
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT INTO spray_attempts
                   (username, password, client_id, endpoint, user_agent, result, error_code, timestamp, proxy_used)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    attempt.username,
                    attempt.password,
                    attempt.client_id,
                    attempt.endpoint,
                    attempt.user_agent,
                    attempt.result.value,
                    attempt.error_code,
                    attempt.timestamp.isoformat(),
                    attempt.proxy_used,
                ),
            )

    def record_valid_credential(self, cred: ValidCredential) -> None:
        """Store a confirmed valid credential (SUCCESS, MFA_REQUIRED, etc.).

        Args:
            cred: The valid credential to store.
        """
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT INTO valid_credentials
                   (username, password, result, discovered_at, mfa_type)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    cred.username,
                    cred.password,
                    cred.result.value,
                    cred.discovered_at.isoformat(),
                    cred.mfa_type,
                ),
            )

    def store_token(self, token: Token) -> None:
        """Store an OAuth token set captured from a successful auth flow.

        Args:
            token: The token to store, including access/refresh/id tokens
                and metadata about the client ID and resource.
        """
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT INTO tokens
                   (username, access_token, refresh_token, id_token, client_id, resource, expires_at, is_foci)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    token.username,
                    token.access_token,
                    token.refresh_token,
                    token.id_token,
                    token.client_id,
                    token.resource,
                    token.expires_at.isoformat() if token.expires_at else "",
                    1 if token.is_foci else 0,
                ),
            )

    def record_enum_result(self, result: EnumResult) -> None:
        """Store a user enumeration result (exists or not).

        Args:
            result: The enumeration result to store.
        """
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT INTO enum_results
                   (username, method, exists_flag, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (
                    result.username,
                    result.method,
                    1 if result.exists else 0,
                    result.timestamp.isoformat(),
                ),
            )

    def record_locked_account(self, locked: LockedAccount) -> None:
        """Record that an account has been locked out during spraying.

        Args:
            locked: The locked account record to store.
        """
        with self._transaction() as cursor:
            cursor.execute(
                """INSERT INTO locked_accounts
                   (username, locked_at, attempt_count)
                   VALUES (?, ?, ?)""",
                (
                    locked.username,
                    locked.locked_at.isoformat(),
                    locked.attempt_count,
                ),
            )

    # -- Query methods --

    def get_valid_credentials(self) -> list[ValidCredential]:
        """Return all valid credentials found during spraying.

        Returns:
            List of ``ValidCredential`` objects, one per confirmed valid login.
        """
        cursor = self._conn.execute("SELECT * FROM valid_credentials")
        return [
            ValidCredential(
                username=row["username"],
                password=row["password"],
                result=AuthResult(row["result"]),
                discovered_at=datetime.fromisoformat(row["discovered_at"]),
                mfa_type=row["mfa_type"],
            )
            for row in cursor.fetchall()
        ]

    def get_locked_accounts(self) -> list[LockedAccount]:
        """Return all accounts that were locked during spraying.

        Returns:
            List of ``LockedAccount`` objects.
        """
        cursor = self._conn.execute("SELECT * FROM locked_accounts")
        return [
            LockedAccount(
                username=row["username"],
                locked_at=datetime.fromisoformat(row["locked_at"]),
                attempt_count=row["attempt_count"],
            )
            for row in cursor.fetchall()
        ]

    def get_attempted_pairs(self) -> set[tuple[str, str]]:
        """Return all (username, password) pairs already attempted — used for resume."""
        cursor = self._conn.execute("SELECT username, password FROM spray_attempts")
        return {(row["username"], row["password"]) for row in cursor.fetchall()}

    def get_tokens(self) -> list[Token]:
        """Return all stored OAuth tokens (both initial and FOCI-exchanged).

        Returns:
            List of ``Token`` objects including access, refresh, and id tokens.
        """
        cursor = self._conn.execute("SELECT * FROM tokens")
        return [
            Token(
                username=row["username"],
                access_token=row["access_token"],
                refresh_token=row["refresh_token"],
                id_token=row["id_token"],
                client_id=row["client_id"],
                resource=row["resource"],
                expires_at=(
                    datetime.fromisoformat(row["expires_at"])
                    if row["expires_at"]
                    else None
                ),
                is_foci=bool(row["is_foci"]),
            )
            for row in cursor.fetchall()
        ]

    def get_enum_results(self) -> list[EnumResult]:
        """Return all user enumeration results.

        Returns:
            List of ``EnumResult`` objects with existence flags.
        """
        cursor = self._conn.execute("SELECT * FROM enum_results")
        return [
            EnumResult(
                username=row["username"],
                method=row["method"],
                exists=bool(row["exists_flag"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
            )
            for row in cursor.fetchall()
        ]

    def get_spray_metadata(self, key: str) -> str | None:
        """Retrieve a metadata value by key from the spray_metadata table.

        Used for session-level data like the target domain.

        Args:
            key: The metadata key to look up.

        Returns:
            The value string, or ``None`` if the key does not exist.
        """
        cursor = self._conn.execute(
            "SELECT value FROM spray_metadata WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_spray_metadata(self, key: str, value: str) -> None:
        """Store or update a metadata key/value pair.

        Uses ``INSERT OR REPLACE`` so existing keys are overwritten.

        Args:
            key: The metadata key.
            value: The metadata value.
        """
        with self._transaction() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO spray_metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def close(self) -> None:
        """Close the database connection.

        Called automatically when using ``StateDB`` as a context manager.
        """
        self._conn.close()
