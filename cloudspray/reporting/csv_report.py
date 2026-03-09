"""CSV report generation from the state database.

Produces a flat CSV file with one row per valid credential found during
spraying. The CSV format is designed for easy import into spreadsheets
or other tools that consume tabular data.

Columns: ``username, password, result, error_code, mfa_type, timestamp``

The ``error_code`` column maps the ``AuthResult`` back to a representative
AADSTS error code for reference (e.g. ``50076`` for MFA_REQUIRED).
"""

import csv
from pathlib import Path

from cloudspray.constants.error_codes import AADSTS_MAP, AuthResult
from cloudspray.state.db import StateDB


class CSVReporter:
    """Export spray results as flat CSV.

    Args:
        db: The state database to read valid credentials from.
    """

    def __init__(self, db: StateDB):
        self._db = db

    def generate(self, output_path: str) -> None:
        """Generate CSV with columns:
        username, password, result, error_code, mfa_type, timestamp

        One row per valid credential found.
        """
        valid_creds = self._db.get_valid_credentials()

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "username",
                "password",
                "result",
                "error_code",
                "mfa_type",
                "timestamp",
            ])

            for cred in valid_creds:
                # Map result back to the AADSTS code for the error_code column
                error_code = _result_to_error_code(cred.result)

                writer.writerow([
                    cred.username,
                    cred.password,
                    cred.result.value,
                    error_code,
                    cred.mfa_type,
                    cred.discovered_at.isoformat(),
                ])


def _result_to_error_code(result: AuthResult) -> str:
    """Map an AuthResult back to a representative AADSTS error code.

    Since multiple AADSTS codes can map to the same AuthResult (see
    ``AADSTS_MAP``), this returns the first matching code found.
    For SUCCESS results (which have no error code), returns an empty string.

    Args:
        result: The auth result to reverse-map.

    Returns:
        The AADSTS error code string, or empty string if not applicable.
    """
    if result == AuthResult.SUCCESS:
        return ""

    # Walk the map and return the first code that maps to this result
    for code, mapped_result in AADSTS_MAP.items():
        if mapped_result == result:
            return code

    return ""
