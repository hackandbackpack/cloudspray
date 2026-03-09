"""Microsoft first-party OAuth client IDs for authentication requests.

Every OAuth authentication request to Azure AD requires a ``client_id``
parameter identifying which application is requesting access. CloudSpray
uses real Microsoft first-party client IDs to make spray requests appear
as legitimate sign-in attempts from known Microsoft applications.

The IDs are split into two categories:

**FOCI (Family of Client IDs)** -- These applications participate in
Microsoft's Family of Client IDs program. The key property is that a
refresh token obtained for one FOCI app can be exchanged for tokens
targeting any other FOCI app. This means a single successful login
can be leveraged to access OneDrive, Teams, Outlook, SharePoint, and
many other services without re-authenticating.

**Non-FOCI** -- These are also first-party Microsoft apps but do NOT
share refresh tokens. They are still useful for CA probing because
conditional access policies may allow certain client IDs while
blocking others.

``ALL_CLIENT_IDS`` is a combined dict used by the CA probe module to
test every possible client ID for policy gaps.
"""

# FOCI apps share refresh tokens -- a token obtained for one FOCI app
# can be exchanged for tokens to any other FOCI app via the Token Manager.
FOCI_CLIENT_IDS: dict[str, str] = {
    "Microsoft Office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "Microsoft Outlook": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "Microsoft Edge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "Microsoft Bing": "cf36b471-5b44-428c-9ce7-313bf84528de",
    "Microsoft Office 365 Portal": "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7",
    "Microsoft OneDrive": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "Microsoft SharePoint": "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
    "Microsoft Planner": "66375f6b-983f-4c2c-9701-d680650f588f",
    "Microsoft OneNote": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "Microsoft Power Automate": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "Microsoft Power BI": "871c010f-5e61-4fb1-83ac-98610a7e9110",
    "Microsoft Yammer": "00000005-0000-0ff1-ce00-000000000000",
    "Microsoft To-Do": "22098786-6e16-43cc-a27d-191a01a1e3b5",
    "Microsoft Whiteboard": "57336123-6e14-4571-8f63-d67d3e1e2c48",
    "Microsoft Stream": "cf53fce8-def6-4aeb-8d30-b158e7b1cf83",
    "Microsoft Sway": "905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba",
    "Microsoft Forms": "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87",
    "Microsoft Intune Company Portal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000",
    "Microsoft Azure CLI": "04b07795-ee44-4fd0-9de8-28a23e5ed958",
    "Microsoft Visual Studio": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "OneDrive iOS": "af124e86-4e96-495a-b70a-90f90ab96707",
    "OneDrive SyncEngine": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "Accounts Control UI": "a40d7d7d-59aa-447e-a655-679a4107e548",
    "Microsoft Authenticator": "4813382a-8fa7-425e-ab75-3b753aab3abb",
}

# Non-FOCI apps do not share refresh tokens but are useful for CA probing
# since conditional access policies may treat different client IDs differently.
NON_FOCI_CLIENT_IDS: dict[str, str] = {
    "Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    "Graph API Explorer": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
    "Azure Active Directory PowerShell": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "Azure PowerShell": "1950a258-227b-4e31-a9cf-717495945fc2",
    "Microsoft Graph PowerShell": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
    "Windows Azure Service Management API": "84070985-06ea-4573-7061-2b2b1c0eadfa",
    "Microsoft Intune": "d4ebce55-015a-49b5-a083-c84d1797ae8c",
    "Microsoft Dynamics 365": "00000007-0000-0000-c000-000000000000",
    "Microsoft Azure Information Protection": "c00e9d32-3c8d-4a7d-832b-029040e7db99",
    "Windows Search": "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "Windows Spotlight": "1f5530b3-261a-47a9-b01e-225283911a71",
    "Microsoft Office Hub": "4765445b-32c6-49b0-83e6-1d93765276ca",
    "Microsoft Autopilot": "0ec893e0-5785-4de6-99da-4ed124e5296c",
    "Microsoft Defender for Endpoint": "fc780465-2017-40d4-a0c5-307022471b92",
    "Microsoft Rights Management Services": "00000012-0000-0000-c000-000000000000",
    "Azure DevOps": "499b84ac-1321-427f-aa17-267ca6975798",
    "Microsoft Substrate Management": "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "Microsoft Managed Desktop": "0000000a-0000-0000-c000-000000000000",
    "SharePoint Online Management Shell": "9bc3ab49-b65d-410a-85ad-de819febfddc",
    "Windows Configuration Designer": "de0853a1-ab20-47bd-990b-71ad5077ac7b",
    "Microsoft Store": "28b567f6-162c-4f54-99a0-6887f387bbcc",
}

# Combined dict of all client IDs, used by CA probe to test every possible
# client/endpoint combination for conditional access policy gaps.
ALL_CLIENT_IDS: dict[str, str] = {**FOCI_CLIENT_IDS, **NON_FOCI_CLIENT_IDS}
