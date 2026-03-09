"""Shared utility functions used across all CloudSpray modules.

This module provides:

- **Logging setup** -- Configures a ``Rich``-powered console logger with
  optional file output. Called once at CLI startup.
- **File I/O helpers** -- Functions to read user lists and password lists
  from disk, with comment stripping that can be toggled off for password
  files (where ``#`` is a valid password character).
- **Email normalization** -- Converts bare usernames to full email addresses
  by appending the target domain.
- **Random suffix generation** -- Short random strings for unique naming
  (used by proxy infrastructure for gateway/container names).
"""

import logging
import random
import string
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(level: str = "INFO", logfile: str | None = None) -> logging.Logger:
    """Configure structured logging with Rich console output and optional file sink.

    Creates the root ``cloudspray`` logger with a Rich console handler for
    colorized, timestamp-prefixed output. If *logfile* is provided, a second
    handler writes all messages (including DEBUG) to that file for later review.

    On repeated calls (e.g. during tests), the logger level is updated but
    duplicate handlers are not added.

    Args:
        level: Logging level string ("DEBUG", "INFO", "WARNING", "ERROR").
        logfile: Optional path to a log file. When set, all log messages
            are also written to this file regardless of the console level.

    Returns:
        The configured ``cloudspray`` logger instance.
    """
    logger = logging.getLogger("cloudspray")

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    console_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.DEBUG)
    console_fmt = logging.Formatter("%(message)s", datefmt="[%X]")
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    if logfile:
        file_handler = logging.FileHandler(logfile, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger


def random_suffix(length: int = 8) -> str:
    """Generate a short random alphanumeric string for unique naming.

    Used to create unique identifiers for proxy infrastructure resources
    (e.g. Fireprox API Gateway names, ACI container names).

    Args:
        length: Number of characters in the suffix.

    Returns:
        A lowercase alphanumeric string of the given length.
    """
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def read_lines(filepath: str | Path, *, skip_comments: bool = True) -> list[str]:
    """Read a file and return non-empty, stripped lines.

    This is the base file reader used by both :func:`read_userlist` and
    :func:`read_password_list`. Each line is stripped of leading/trailing
    whitespace, and blank lines are always skipped.

    Args:
        filepath: Path to the input file.
        skip_comments: When ``True``, lines starting with ``#`` are dropped.
            Set to ``False`` for password lists where ``#`` is a valid
            password character.

    Returns:
        List of cleaned, non-empty lines from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    lines = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if skip_comments and stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def normalize_email(username: str, domain: str) -> str:
    """Ensure a username is a fully-qualified email address.

    If the username already contains ``@``, it is returned as-is.
    Otherwise, ``@domain`` is appended.

    Args:
        username: A bare username ("jsmith") or full email ("jsmith@contoso.com").
        domain: The target domain to append if needed.

    Returns:
        A full email address string.
    """
    if "@" in username:
        return username
    return f"{username}@{domain}"


def read_userlist(filepath: str | Path) -> list[str]:
    """Read a list of usernames/emails from a file, one per line.

    Comment lines (starting with ``#``) are skipped so the user can
    annotate their lists.

    Args:
        filepath: Path to the user list file.

    Returns:
        List of username/email strings.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    return read_lines(filepath)


def read_password_list(filepath: str | Path) -> list[str]:
    """Read a list of passwords from a file, one per line.

    Comment stripping is disabled so passwords like ``#Summer2024!`` are
    preserved. Only blank lines are skipped.

    Args:
        filepath: Path to the password list file.

    Returns:
        List of password strings.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    return read_lines(filepath, skip_comments=False)
