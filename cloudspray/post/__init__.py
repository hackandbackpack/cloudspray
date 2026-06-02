"""Post-exploitation modules for leveraging valid credentials.

After the spray finds valid credentials, these modules demonstrate
the impact of the compromise:

- **TokenManager** -- Captures OAuth tokens via ROPC (Resource Owner Password
  Credential) flow and performs FOCI (Family of Client IDs) refresh token
  exchange to mint tokens for many Microsoft services from a single login.

- **CAProbe** -- Tests every combination of client ID and resource endpoint
  against credentials blocked by MFA or Conditional Access to find policy
  gaps that allow bypass. Similar in approach to MFASweep.

- **GraphExfil** -- Uses captured Graph API tokens to demonstrate data access
  by listing OneDrive files, reading recent emails, and enumerating Teams
  conversations.

All modules read from and write to the shared SQLite state database, so
their results are available for reporting.
"""

from cloudspray.post.ca_probe import CAProbe
from cloudspray.post.exfil import GraphExfil
from cloudspray.post.tokens import TokenManager

__all__ = [
    "TokenManager",
    "CAProbe",
    "GraphExfil",
]
