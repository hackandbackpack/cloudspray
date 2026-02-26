import logging
from pathlib import Path

from rich.logging import RichHandler


def setup_logging(level: str = "INFO", logfile: str | None = None) -> logging.Logger:
    """Configure structured logging with Rich console output and optional file sink."""
    logger = logging.getLogger("cloudspray")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return logger

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


def read_lines(filepath: str | Path) -> list[str]:
    """Read a file and return non-empty, stripped lines (skipping comments)."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    lines = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def read_userlist(filepath: str | Path) -> list[str]:
    """Read a list of usernames/emails from a file, one per line."""
    return read_lines(filepath)


def read_password_list(filepath: str | Path) -> list[str]:
    """Read a list of passwords from a file, one per line."""
    return read_lines(filepath)
