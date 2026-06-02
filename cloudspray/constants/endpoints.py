"""Microsoft resource endpoint URLs for token requests and API calls.

These are the ``resource`` / ``audience`` URLs passed to Azure AD during
OAuth token requests. Each endpoint represents a different Microsoft service
that tokens can be scoped to.

The spray engine uses these to request tokens for specific services, and the
CA probe module iterates all endpoints combined with all client IDs to find
conditional access policy gaps (a specific client + endpoint combination
may bypass MFA or CA restrictions even when others are blocked).

Note: The SharePoint entry uses ``{tenant}`` as a placeholder. At runtime,
this is replaced with the target organization's tenant slug (e.g.
``example`` from ``example.com``).
"""

ENDPOINTS: dict[str, str] = {
    "Microsoft Graph": "https://graph.microsoft.com",
    "Azure Management": "https://management.azure.com",
    "Office 365 Exchange": "https://outlook.office365.com",
    "Office 365 SharePoint": "https://{tenant}.sharepoint.com",
    "Azure AD Graph": "https://graph.windows.net",
    "Azure Key Vault": "https://vault.azure.net",
    "OneNote": "https://onenote.com",
    "Microsoft Teams": "https://api.spaces.skype.com",
    "Outlook": "https://outlook.office.com",
    "Substrate": "https://substrate.office.com",
    "Microsoft Service Management": "https://management.core.windows.net",
}
