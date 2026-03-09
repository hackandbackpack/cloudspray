"""Entry point for ``python -m cloudspray``.

This module bootstraps the Click CLI defined in :mod:`cloudspray.cli`.
If required dependencies (Click, Rich, etc.) are missing, it prints a
helpful installation message and exits rather than showing a raw traceback.
"""

try:
    from cloudspray.cli import cli
except ImportError:
    import sys

    print(
        "Error: CLI module not yet available. "
        "Install all dependencies with: pip install -e '.[dev]'",
        file=sys.stderr,
    )
    raise SystemExit(1)

cli()
