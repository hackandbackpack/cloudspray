"""JSON report generation from the state database.

Produces a structured JSON file containing the full results of a CloudSpray
engagement. The report is organized into sections:

- **metadata** -- Timestamp, target domain, tool version
- **valid_credentials** -- All confirmed valid username/password pairs with
  exploitability flags (``is_no_mfa``, ``is_mfa_enrollment``)
- **locked_accounts** -- Accounts that were locked during spraying
- **tokens** -- OAuth tokens captured (direct auth and FOCI exchange)
- **statistics** -- Aggregate counts and enumeration results

The JSON report is designed for programmatic consumption by downstream
tools or for import into reporting platforms.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from cloudspray import __version__
from cloudspray.constants.error_codes import AuthResult
from cloudspray.state.db import StateDB


class JSONReporter:
    """Export spray results as structured JSON.

    Args:
        db: The state database to read results from.
    """

    def __init__(self, db: StateDB):
        self._db = db

    def generate(self, output_path: str) -> None:
        """Generate JSON report file.

        Structure:
        - metadata: timestamp, domain, tool version
        - valid_credentials: username, password, result, mfa_type, exploitability flags
        - locked_accounts: username, locked_at
        - tokens: username, client_id, resource, is_foci
        - statistics: total_attempts, valid_count, locked_count, enum_results
        """
        valid_creds = self._db.get_valid_credentials()
        locked_accounts = self._db.get_locked_accounts()
        tokens = self._db.get_tokens()
        all_attempts = self._db.get_all_attempts()
        enum_results = self._db.get_enum_results()

        domain = self._db.get_spray_metadata("domain") or ""

        # Build result breakdown for summary
        result_counts: dict[str, int] = {}
        for attempt in all_attempts:
            key = attempt.result.value
            result_counts[key] = result_counts.get(key, 0) + 1

        report = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "domain": domain,
                "version": __version__,
            },
            "summary": {
                "total_attempts": len(all_attempts),
                "valid_credentials": len(valid_creds),
                "locked_accounts": len(locked_accounts),
                "results_by_type": result_counts,
            },
            "valid_credentials": [
                {
                    "username": cred.username,
                    "password": cred.password,
                    "result": cred.result.value,
                    "mfa_type": cred.mfa_type,
                    "is_mfa_enrollment": cred.result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
                    "is_no_mfa": cred.result == AuthResult.SUCCESS,
                }
                for cred in valid_creds
            ],
            "locked_accounts": [
                {
                    "username": acct.username,
                    "locked_at": acct.locked_at.isoformat(),
                }
                for acct in locked_accounts
            ],
            "tokens": [
                {
                    "username": tok.username,
                    "client_id": tok.client_id,
                    "resource": tok.resource,
                    "is_foci": tok.is_foci,
                    "expires_at": tok.expires_at.isoformat() if tok.expires_at else None,
                }
                for tok in tokens
            ],
            "spray_log": [
                {
                    "username": a.username,
                    "password": a.password,
                    "result": a.result.value,
                    "error_code": a.error_code,
                    "client_id": a.client_id,
                    "endpoint": a.endpoint,
                    "user_agent": a.user_agent,
                    "proxy_used": a.proxy_used,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in all_attempts
            ],
            "enum_results": [
                {
                    "username": er.username,
                    "method": er.method,
                    "exists": er.exists,
                }
                for er in enum_results
            ],
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
