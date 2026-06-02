"""Entry point for ``python -m cloudspray``.

Entry point for ``python -m cloudspray``.
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
