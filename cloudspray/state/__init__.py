"""SQLite-backed state persistence for crash/resume support.

The state package provides two things:

1. **Data models** (:mod:`cloudspray.state.models`) -- Dataclasses representing
   spray attempts, valid credentials, tokens, enum results, and locked accounts.
   These are the structured records that flow through the system.

2. **Database layer** (:mod:`cloudspray.state.db`) -- ``StateDB`` wraps a SQLite
   database that records every spray attempt, valid credential, captured token,
   and enumeration result. This serves two purposes:

   - **Resume support**: If a spray is interrupted (Ctrl-C, crash, network
     failure), the next run with ``--resume`` queries ``get_attempted_pairs()``
     to skip already-tried username/password combinations.

   - **Reporting**: The ``report`` command reads all results from the database
     to generate JSON or CSV reports without needing to re-run the spray.

The database uses WAL (Write-Ahead Logging) mode for concurrent read/write
safety, and all writes go through a thread-locked transaction context manager
to prevent corruption from multi-threaded access.
"""

from cloudspray.state.db import StateDB
from cloudspray.state.models import (
    EnumResult,
    LockedAccount,
    SprayAttempt,
    Token,
    ValidCredential,
)

__all__ = [
    "StateDB",
    "EnumResult",
    "LockedAccount",
    "SprayAttempt",
    "Token",
    "ValidCredential",
]
