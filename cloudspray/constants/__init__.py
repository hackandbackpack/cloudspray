"""Microsoft-specific constants for Azure AD authentication operations.

This package centralizes all the hardcoded Microsoft values that CloudSpray
needs to interact with Azure AD / M365 authentication endpoints:

- **client_ids** -- OAuth client IDs for first-party Microsoft applications,
  split into FOCI (Family of Client IDs) and non-FOCI groups.
- **endpoints** -- Microsoft resource endpoint URLs (Graph, Exchange, SharePoint, etc.).
- **error_codes** -- AADSTS error code mappings and the ``AuthResult`` enum.
- **user_agents** -- Realistic browser/client User-Agent strings for request rotation.

These constants are imported and used throughout the spray engine, post-exploitation
modules, and conditional access probing logic.
"""

from cloudspray.constants.client_ids import ALL_CLIENT_IDS, FOCI_CLIENT_IDS, NON_FOCI_CLIENT_IDS
from cloudspray.constants.endpoints import ENDPOINTS
from cloudspray.constants.error_codes import AADSTS_MAP, AuthResult
from cloudspray.constants.user_agents import USER_AGENTS

__all__ = [
    "ALL_CLIENT_IDS",
    "FOCI_CLIENT_IDS",
    "NON_FOCI_CLIENT_IDS",
    "ENDPOINTS",
    "USER_AGENTS",
    "AuthResult",
    "AADSTS_MAP",
]
