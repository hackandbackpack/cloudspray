"""CloudSpray -- Azure AD password sprayer and user enumerator for authorized penetration testing.

CloudSpray is a modular toolkit for testing Microsoft 365 / Azure AD authentication
security. It supports:

- **User enumeration** via OneDrive, Teams, MSOL, and login endpoint techniques
- **Password spraying** with configurable timing, jitter, and lockout safety
- **Post-exploitation** including FOCI token exchange, conditional access probing,
  and lightweight Graph API data access checks
- **Reporting** in JSON and CSV formats

Architecture overview:

    cloudspray/
        cli.py          -- Click-based CLI entry point (enum, spray, post, report)
        config.py       -- YAML config loading with dataclass defaults
        constants/      -- Microsoft OAuth client IDs, endpoints, error codes, UAs
        state/          -- SQLite persistence for crash/resume and results
        enum/           -- User enumeration modules
        spray/          -- Password spray engine and authentication
        post/           -- Post-exploitation modules (tokens, CA probe, exfil)
        proxy/          -- Fireprox / AWS API Gateway proxy rotation
        reporting/      -- Console, JSON, and CSV output formatters
        utils.py        -- Logging setup, file I/O, and shared helpers

The package is designed to be run as ``python -m cloudspray`` or installed via pip
and invoked as ``cloudspray`` on the command line.
"""

__version__ = "0.1.0"
