# Microsoft resource endpoints used for token requests and API calls.
# The SharePoint entry is a template — replace {tenant} with the target org.

ENDPOINTS: dict[str, str] = {
    "Microsoft Graph": "https://graph.microsoft.com",
    "Azure Management": "https://management.azure.com",
    "Office 365 Exchange": "https://outlook.office365.com",
    "Office 365 SharePoint": "https://{tenant}.sharepoint.com",
    "Windows Net": "https://graph.windows.net",
    "Azure Key Vault": "https://vault.azure.net",
    "OneNote": "https://onenote.com",
    "Microsoft Teams": "https://api.spaces.skype.com",
    "Outlook": "https://outlook.office.com",
    "Substrate": "https://substrate.office.com",
    "Azure AD Graph": "https://graph.windows.net",
    "Microsoft Service Management": "https://management.core.windows.net",
}
