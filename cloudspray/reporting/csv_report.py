"""CSV report generation from the state database.

Produces a CSV file with one row per spray attempt, showing the full log of
what happened during the engagement. Valid credentials are marked in the
result column (success, valid_password_mfa_required, etc.).

Columns: ``username, password, result, error_code, client_id, endpoint, proxy_used, timestamp``
"""

import csv
from pathlib import Path

from cloudspray.state.db import StateDB


class CSVReporter:
    """Export spray results as flat CSV.

    Args:
        db: The state database to read results from.
    """

    def __init__(self, db: StateDB):
        self._db = db

    def generate(self, output_path: str) -> None:
        """Generate CSV with every spray attempt as a row."""
        all_attempts = self._db.get_all_attempts()

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "username",
                "password",
                "result",
                "error_code",
                "client_id",
                "endpoint",
                "proxy_used",
                "timestamp",
            ])

            for attempt in all_attempts:
                writer.writerow([
                    attempt.username,
                    attempt.password,
                    attempt.result.value,
                    attempt.error_code,
                    attempt.client_id,
                    attempt.endpoint,
                    attempt.proxy_used,
                    attempt.timestamp.isoformat(),
                ])
