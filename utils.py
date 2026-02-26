import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(level: str = "INFO", logfile: str | None = None) -> logging.Logger:
    """Configure structured logging with Rich console output and optional file sink."""
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


def read_lines(filepath: str | Path, *, skip_comments: bool = True) -> list[str]:
    """Read a file and return non-empty, stripped lines.

    Args:
        filepath: Path to the input file.
        skip_comments: When True, lines starting with '#' are dropped.
            Set to False for password lists where '#' is a valid character.
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

    If the username already contains '@', it is returned as-is.
    Otherwise, the domain is appended.
    """
    if "@" in username:
        return username
    return f"{username}@{domain}"


def read_userlist(filepath: str | Path) -> list[str]:
    """Read a list of usernames/emails from a file, one per line."""
    return read_lines(filepath)


def read_password_list(filepath: str | Path) -> list[str]:
    """Read a list of passwords from a file, one per line.

    Comment stripping is disabled so passwords like '#Summer2024!' are preserved.
    """
    return read_lines(filepath, skip_comments=False)
