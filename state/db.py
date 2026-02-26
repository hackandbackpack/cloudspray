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
    """

    def __init__(self, db_path: str | Path):
        self._conn = sqlite3.connect(
            str(db_path),
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._create_tables()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _create_tables(self) -> None:
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
        cursor = self._conn.execute(
            "SELECT value FROM spray_metadata WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_spray_metadata(self, key: str, value: str) -> None:
        with self._transaction() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO spray_metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def close(self) -> None:
        self._conn.close()
