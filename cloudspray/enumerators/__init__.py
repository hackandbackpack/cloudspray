"""User enumeration techniques for Microsoft 365 / Azure AD.

This package provides multiple strategies for discovering valid user accounts
in a target Azure AD tenant during authorized penetration tests. Each technique
trades off between stealth and reliability:

Techniques (ordered from quietest to noisiest):
    OneDriveEnumerator
        Probes SharePoint personal-site URLs. Completely unauthenticated and
        generates no sign-in log entries, but only works when the tenant has
        OneDrive provisioned for users.
    MSOLEnumerator
        Queries the public GetCredentialType endpoint. Unauthenticated and does
        not create sign-in events, but Microsoft applies aggressive throttling
        that can return ambiguous results under heavy use.
    TeamsEnumerator
        Uses the Teams external-search API. Requires a sacrificial M365 account
        for authentication. Moderately noisy because the search calls are logged,
        but the target users themselves see no sign-in activity.
    LoginEnumerator
        Attempts ROPC (Resource Owner Password Credential) authentication with a
        deliberately wrong password, then interprets the AADSTS error code. The
        noisiest option: every probe creates a failed-login event in the target
        tenant's Azure AD sign-in logs.

All enumerators follow the same interface:
    1. Instantiate with the target domain, a StateDB for persistence, and a
       ConsoleReporter for output.
    2. Call ``enumerate(usernames)`` with a list of candidate email addresses.
    3. Receive back a list of confirmed-valid addresses.

Results are persisted to the state database so downstream modules (password
spraying, post-auth) can consume them without re-enumerating.

Typical usage from the CLI layer::

    from cloudspray.enumerators import OneDriveEnumerator

    enumerator = OneDriveEnumerator(domain, db, reporter)
    valid_users = enumerator.enumerate(candidate_list)
"""

from cloudspray.enumerators.login import LoginEnumerator
from cloudspray.enumerators.msol import MSOLEnumerator
from cloudspray.enumerators.onedrive import OneDriveEnumerator
from cloudspray.enumerators.teams import TeamsEnumerator

__all__ = [
    "LoginEnumerator",
    "MSOLEnumerator",
    "OneDriveEnumerator",
    "TeamsEnumerator",
]
