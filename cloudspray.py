#!/usr/bin/env python3
"""CloudSpray - M365 password sprayer and user enumerator.

Run this script directly:
    python3 cloudspray.py enum -d example.com -u users.txt -m msol
    python3 cloudspray.py spray -d example.com -u users.txt -P 'Password1!'
"""

import os
import sys

# Add the repo directory to the Python path so the cloudspray package
# can be imported regardless of where the script is run from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from cloudspray.cli import cli
except ImportError as exc:
    print(
        f"Missing dependency: {exc}\n"
        "Install requirements with: pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1)

if __name__ == "__main__":
    cli()
