"""Password spray module for M365 authentication testing.

This package implements the core spray pipeline used during authorized penetration
tests against Microsoft 365 / Azure AD tenants. The pipeline has four stages:

1. **Shuffle** -- Generate (username, password) pairs in a randomized order to
   avoid sequential lockouts and reduce detection by Azure AD's smart-lockout
   heuristics. Two strategies are available: standard (password-round ordering
   with shuffled users) and aggressive (fully random pair ordering).

2. **Auth** -- Send each pair to Azure AD using Microsoft's Resource Owner
   Password Credential (ROPC) OAuth2 flow via the MSAL library. Each attempt
   rotates the client ID, target resource endpoint, and User-Agent header to
   make traffic look like it originates from different first-party Microsoft
   applications, reducing fingerprinting risk.

3. **Classify** -- Parse the MSAL response and extract AADSTS error codes from
   the error description. Each code maps to a semantic outcome such as
   ``INVALID_PASSWORD``, ``VALID_PASSWORD_MFA_REQUIRED``, ``ACCOUNT_LOCKED``,
   etc. This lets the engine react to each outcome appropriately.

4. **Engine** -- Orchestrate the full campaign: enforce per-user timing delays,
   track lockouts with a cooldown window, implement a circuit breaker that halts
   the spray when too many consecutive lockouts occur, handle rate-limit
   back-off, support resume from prior state, and report results.

Typical usage from the CLI layer::

    from cloudspray.spray import Authenticator, SprayEngine

    auth = Authenticator(domain="contoso.com", proxy_session=session)
    engine = SprayEngine(config, db, auth, reporter)
    engine.run(users, passwords)
"""

from cloudspray.spray.auth import Authenticator
from cloudspray.spray.classifier import classify_auth_result
from cloudspray.spray.engine import SprayEngine
from cloudspray.spray.shuffle import aggressive_shuffle, standard_shuffle

__all__ = [
    "Authenticator",
    "SprayEngine",
    "aggressive_shuffle",
    "classify_auth_result",
    "standard_shuffle",
]
