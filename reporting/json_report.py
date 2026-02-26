import json
from datetime import datetime, timezone
from pathlib import Path

from cloudspray import __version__
from cloudspray.constants.error_codes import AuthResult
from cloudspray.state.db import StateDB


class JSONReporter:
    """Export spray results as structured JSON."""

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
        attempted_pairs = self._db.get_attempted_pairs()
        enum_results = self._db.get_enum_results()

        domain = self._db.get_spray_metadata("domain") or ""

        report = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "domain": domain,
                "version": __version__,
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
                }
                for tok in tokens
            ],
            "statistics": {
                "total_attempts": len(attempted_pairs),
                "valid_count": len(valid_creds),
                "locked_count": len(locked_accounts),
                "enum_results": [
                    {
                        "username": er.username,
                        "method": er.method,
                        "exists": er.exists,
                    }
                    for er in enum_results
                ],
            },
        }

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
