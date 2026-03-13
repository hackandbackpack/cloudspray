# Okta Spraying, IdP Recon, and SaaS Footprinting Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Okta password spraying, automated IdP discovery, and SaaS footprinting to CloudSpray so the tool can identify the correct identity provider before spraying and support non-Azure targets.

**Architecture:** Three new CLI commands (`recon`, `okta-spray`, `footprint`) plus federation warnings wired into existing `spray` and `enum` commands. The Okta sprayer is a standalone command (not a provider flag) with its own conservative defaults tuned for Okta's aggressive throttling. All commands reuse existing infrastructure (state DB, Fireprox, reporting, resume).

**Tech Stack:** Python 3, Click CLI, requests, dnspython (new dep for DNS lookups), existing MSAL/Fireprox/SQLite infrastructure.

---

## 1. `recon` Command -- IdP Discovery

**Purpose:** Automated version of the manual steps we used to discover that onelineage.com federates to Okta. Answers "what should I spray against?"

**CLI interface:**
```bash
cloudspray.py recon -d onelineage.com
```

**Steps performed:**
1. Azure AD OIDC discovery -- confirm tenant exists, extract tenant ID
2. `getuserrealm.srf` query -- get NameSpaceType (Managed/Federated), FederationBrandName
3. DNS TXT record lookup -- parse for `DirectFedAuthUrl` to detect external IdP (Okta, ADFS, PingFederate)
4. Autodiscover CNAME check -- determines if M365 services are in use
5. MX record check -- identifies mail provider (Proofpoint, M365, Google, etc.)

**Output:**
```
> Tenant: onelineage.com (ID: abc123...)
> Namespace: Managed
> Federation Brand: Lineage
> Identity Provider: Okta (https://lineage.okta.com/...)
> Mail: Proofpoint gateway (pphosted.com)
> Autodiscover: outlook.com (M365 services in use)
>
> WARNING: This domain federates to Okta.
> Azure AD ROPC spray will likely fail -- use 'okta-spray' instead.
```

**IdP detection patterns in TXT records:**
- `DirectFedAuthUrl=https://*.okta.com/*` -> Okta
- `DirectFedAuthUrl=https://*/adfs/*` -> ADFS
- `DirectFedAuthUrl=https://*.pingidentity.com/*` or `*/pingfederate/*` -> PingFederate
- `DirectFedAuthUrl=https://*.duosecurity.com/*` -> Duo
- Other `DirectFedAuthUrl` values -> Unknown federation provider (display URL)

---

## 2. `okta-spray` Command -- Okta Password Spraying

**Purpose:** Dedicated Okta sprayer with conservative defaults. Separate from the Azure spray command.

**CLI interface:**
```bash
# Auto-discover Okta URL from domain TXT records
cloudspray.py okta-spray -d onelineage.com -u users.txt -p passwords.txt

# Specify Okta URL directly (skips auto-discovery)
cloudspray.py okta-spray --okta-url https://lineage.okta.com -u users.txt -p passwords.txt
```

**Authentication flow:**
- Endpoint: `POST https://{subdomain}.okta.com/api/v1/authn`
- Request body: `{"username": "user@domain.com", "password": "password"}`
- Headers mimic Okta Sign-In Widget:
  - `Content-Type: application/json`
  - `Accept: application/json`
  - `X-Okta-User-Agent-Extended: okta-signin-widget-2.12.0`
  - Rotated `User-Agent` strings

**Response classification (maps to existing AuthResult enum):**

| HTTP | Response | AuthResult |
|------|----------|------------|
| 200 | `status: SUCCESS` | `SUCCESS` |
| 200 | `status: MFA_REQUIRED` | `VALID_PASSWORD_MFA_REQUIRED` |
| 200 | `status: MFA_ENROLL` | `VALID_PASSWORD_MFA_ENROLLMENT` |
| 200 | `status: LOCKED_OUT` | `ACCOUNT_LOCKED` |
| 200 | `status: PASSWORD_EXPIRED` | `VALID_PASSWORD_EXPIRED` |
| 401 | `errorCode: E0000004` | `INVALID_PASSWORD` |
| 429 | `errorCode: E0000047` | `RATE_LIMITED` |

**Okta-tuned defaults:**
- `delay`: 60s (double Azure default, Okta throttles aggressively)
- `jitter`: 15s
- Single-threaded (no concurrent requests)
- Rate limit back-off: 120s then retry (double Azure's 60s)

**What it reuses from existing infrastructure:**
- Fireprox proxy rotation (gateways target `{subdomain}.okta.com`)
- State DB (spray_attempts, valid_credentials, locked_accounts tables)
- Resume support (skip already-attempted pairs)
- Console reporter (color-coded results, progress bar)
- JSON/CSV report generation
- Circuit breaker (consecutive lockout threshold)
- Email normalization

**Okta URL auto-discovery:**
1. Query DNS TXT records for the domain
2. Parse for `DirectFedAuthUrl` containing `okta.com`
3. Extract the Okta subdomain from the URL
4. If not found, error with: "Could not auto-discover Okta URL. Use --okta-url to specify it."

---

## 3. `footprint` Command -- SaaS Intelligence

**Purpose:** Full DNS-based intelligence dump showing every SaaS service the org uses. Useful for attack surface mapping.

**CLI interface:**
```bash
cloudspray.py footprint -d onelineage.com
```

**What it checks:**
- All TXT records -- parse for domain verification strings
- MX records -- mail provider identification
- CNAME lookups -- autodiscover, lyncdiscover, etc.
- SPF record breakdown -- authorized mail senders

**SaaS detection patterns (TXT record prefix -> service name):**

| Pattern | Service |
|---------|---------|
| `atlassian-domain-verification` | Atlassian |
| `google-site-verification` | Google Workspace |
| `slack-domain-verification` | Slack |
| `1password-site-verification` | 1Password |
| `docusign=` | DocuSign |
| `MS=` | Microsoft 365 |
| `adobe-idp-site-verification` | Adobe |
| `miro-verification` | Miro |
| `airtable-verification` | Airtable |
| `teamviewer-sso-verification` | TeamViewer |
| `box-domain-verification` | Box |
| `smartsheet-site-validation` | Smartsheet |
| `pardot` | Salesforce/Pardot |
| `ciscocidomainverification` | Cisco |
| `apple-domain-verification` | Apple |
| `mandrill_verify` | Mailchimp/Mandrill |
| `DirectFedAuthUrl=` | Federation IdP |
| `v=spf1` | SPF (parsed for mail providers) |

Pattern list is a simple dict -- easy to extend as new services are encountered.

**Output sections:**
```
> Domain: onelineage.com
>
> === Mail ===
> MX: Proofpoint (mxa-00304501.gslb.pphosted.com)
> SPF: Proofpoint (pphosted.com)
> DMARC: reject, reports to Proofpoint
>
> === Identity ===
> Azure AD: Tenant verified (MS=ms38804948)
> IdP: Okta (lineage.okta.com)
> SSO: TeamViewer
>
> === SaaS Footprint ===
> Atlassian, Slack, 1Password, DocuSign, Adobe, Miro,
> Airtable, Smartsheet, Box, Salesforce/Pardot, Apple,
> Cisco, Google, Mailchimp
```

---

## 4. Federation Warning Integration

**Purpose:** Prevent users from wasting time spraying Azure AD against federated domains.

**Where it hooks in:** The existing `_discover_tenant()` function in `cli.py`, called by both `spray` and `enum` commands.

**Behavior:**
1. After confirming the Azure AD tenant exists, do a DNS TXT lookup for `DirectFedAuthUrl`
2. If found, print a warning with the detected IdP and URL
3. Abort unless `--force` is passed

**Output when federation detected:**
```
> Tenant found: onelineage.com (ID: abc123...)
> WARNING: This domain federates authentication to Okta (lineage.okta.com)
> Azure AD spray/enum will likely return user_not_found for all users.
>
> Options:
>   - Use 'okta-spray' command instead
>   - Run 'recon' to see full IdP details
>   - Pass --force to proceed anyway
>
> Aborting. Use --force to override.
```

**Changes to existing commands:**
- `spray` and `enum` gain a `--force` flag
- `_discover_tenant()` gains a federation check step
- No changes to spray engine, authenticator, or state DB

---

## New Dependency

- **dnspython** (`dns.resolver`) -- for MX, TXT, CNAME lookups in recon and footprint commands. Add to `requirements.txt`.

---

## Files Affected

**New files:**
- `cloudspray/recon/discovery.py` -- IdP detection, tenant info, DNS queries
- `cloudspray/recon/__init__.py`
- `cloudspray/recon/footprint.py` -- SaaS pattern matching and DNS dump
- `cloudspray/spray/okta_auth.py` -- Okta authenticator (POST to /api/v1/authn, classify response)

**Modified files:**
- `cloudspray/cli.py` -- Add `recon`, `okta-spray`, `footprint` commands; add `--force` to `spray`/`enum`; extend `_discover_tenant()` with federation check
- `cloudspray/constants/error_codes.py` -- No changes needed (AuthResult enum already covers all Okta response types)
- `requirements.txt` -- Add `dnspython`
