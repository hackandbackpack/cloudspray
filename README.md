# CloudSpray

M365 and Okta password sprayer, user enumerator, and post-exploitation framework with IP rotation for authorized penetration testing.

## What It Does

CloudSpray automates the full lifecycle of cloud identity security assessments:

1. **Reconnaissance** - Discovers tenant info, identity providers, and SaaS footprint from DNS
2. **User Enumeration** - Identifies valid Azure AD accounts using multiple techniques (no authentication required for most methods)
3. **UPN Format Discovery** - Tests common email format patterns against a list of employee names to find the org's naming convention
4. **Password Spraying** - Tests accounts against passwords with safety mechanisms, supporting both Azure AD and Okta
5. **Post-Exploitation** - FOCI token exchange, Conditional Access probing, and data access checks
6. **Reporting** - JSON/CSV export of all results

All requests can be routed through **AWS API Gateway (Fireprox)** or **Azure Container Instances** for IP rotation.

## Project Structure

```
cloudspray/                  # repo root
├── cloudspray.py            # entry point - run this
├── config.json.example      # AWS/Azure credentials template
├── requirements.txt
└── cloudspray/              # package
    ├── cli.py               # Click CLI commands
    ├── settings.py          # Config loading from config.json
    ├── utils.py             # File I/O, logging, helpers
    ├── enumerators/         # User enumeration methods
    ├── spray/               # Password spray engine
    ├── proxy/               # IP rotation (AWS API Gateway + Azure ACI)
    ├── post/                # Post-exploitation modules
    ├── recon/               # Tenant discovery and DNS footprinting
    ├── reporting/           # JSON/CSV output
    ├── state/               # SQLite persistence
    └── constants/           # Microsoft client IDs, endpoints, error codes
```

## Installation

```bash
git clone https://github.com/hackandbackpack/CloudSpray.git
cd CloudSpray

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### 1. Recon

Start by discovering the target's identity provider and cloud services:

```bash
# Tenant info, federation status, identity provider
python3 cloudspray.py recon -d example.com

# DNS-based SaaS footprint (TXT, SPF, MX, DMARC)
python3 cloudspray.py footprint -d example.com
```

### 2. Build a User List

If you have employee names but no email addresses, discover the UPN format first:

```bash
# Test common patterns (first.last, flast, firstl, etc.)
python3 cloudspray.py format -d example.com -n names.txt
```

### 3. Enumerate Users

```bash
# MSOL method (recommended - reliable, no auth required, no sign-in logs)
python3 cloudspray.py enum -d example.com -u userlist.txt -m msol -o valid-users.txt

# OneDrive method (no sign-in logs, but only finds users with OneDrive provisioned)
python3 cloudspray.py enum -d example.com -u userlist.txt -m onedrive -o valid-users.txt
```

### 4. Password Spray

```bash
# Single password against Azure AD
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!'

# Password list
python3 cloudspray.py spray -d example.com -u valid-users.txt -p passwords.txt

# Against Okta
python3 cloudspray.py okta-spray -d example.com -u valid-users.txt -P 'Spring2026!' --okta-url https://example.okta.com
```

### 5. IP Rotation (Recommended)

Set up credentials for proxy rotation. CloudSpray supports AWS API Gateway (Fireprox) and Azure Container Instances:

```bash
cp config.json.example config.json
```

Edit `config.json` with your AWS or Azure credentials. CloudSpray auto-detects which backend has credentials and uses it. You can also force a specific backend:

```bash
# Auto-detect (default)
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!'

# Force AWS Fireprox
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!' --proxy-backend aws

# Force Azure ACI
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!' --proxy-backend azure

# No proxy (direct from your IP)
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!' --proxy-backend none
```

### 6. Post-Exploitation

```bash
# FOCI token exchange - test access across Microsoft services
python3 cloudspray.py post --foci

# Probe for Conditional Access gaps
python3 cloudspray.py post --ca-probe

# Check Graph API data access (read-only)
python3 cloudspray.py post --exfil
```

### 7. Reporting

```bash
# JSON report (passwords redacted in spray log by default)
python3 cloudspray.py report -f json -o results.json

# Include plaintext passwords in spray log
python3 cloudspray.py report -f json -o results.json --no-redact

# CSV report
python3 cloudspray.py report -f csv -o results.csv
```

## Reconnaissance

### Tenant & IdP Discovery

The `recon` command identifies everything you need to know before spraying:

```bash
python3 cloudspray.py recon -d example.com
```

This checks:
- Azure AD tenant existence and tenant ID
- Federation status (managed vs. federated)
- Identity provider detection (Okta, ADFS, PingFederate, Duo)
- MX records for mail provider identification
- Autodiscover CNAME for M365 integration

Use this to determine whether to target Azure AD (`spray`) or Okta (`okta-spray`).

### SaaS Footprinting

The `footprint` command maps an organization's SaaS stack entirely from public DNS data:

```bash
python3 cloudspray.py footprint -d example.com
```

This analyzes:
- TXT records for domain verification entries (Google, Slack, Docusign, Adobe, etc.)
- SPF `include:` directives to map email infrastructure
- MX records for mail provider identification
- DMARC policy (reject/quarantine/none)

Maps 40+ known vendor DNS signatures. Entirely passive, reads publicly available DNS records only.

## UPN Format Discovery

When you have employee names but don't know the email format, the `format` command tests common patterns:

```bash
python3 cloudspray.py format -d example.com -n names.txt
```

Where `names.txt` contains full names (one per line, e.g. "Jane Doe"). CloudSpray tests 11 patterns for each name:

`first.last`, `flast`, `firstl`, `firstlast`, `lastfirst`, `last.first`, `lfirst`, `first_last`, `first-last`, `first`, `last`

Uses the MSOL GetCredentialType endpoint (no sign-in logs generated). Reports the best-matching format so you can build a full user list.

## Tenant Discovery

CloudSpray validates that your target domain resolves to a real Azure AD tenant **before** setting up proxy gateways or sending any spray/enum requests. If you pass a bare tenant name (no dots), it automatically tries common suffixes:

```
-d example        ->  tries example, example.com, example.onmicrosoft.com, example.org, example.net
-d example.com    ->  validates example.com directly
```

On success, it prints the resolved tenant ID so you know you're hitting the right target. On failure, it tells you what it tried and exits.

## Configuration

All settings can be configured in `config.json` and/or overridden with CLI flags. CLI flags always take priority.

### Setup

```bash
cp config.json.example config.json
```

Edit `config.json` with your settings. See the example file for detailed explanations of every field.

### Per-Engagement Config

Use `--config` to point at a different config file per engagement:

```bash
python3 cloudspray.py --config /path/to/engagement/config.json spray -d example.com -u users.txt -P 'Spring2026!'
```

### AWS Credentials (for Fireprox)

Fill in `aws_access_key` and `aws_secret_key` in `config.json`. If left blank, CloudSpray runs without AWS proxy rotation.

### Azure Credentials (for ACI)

Fill in `azure_subscription_id`, `azure_client_id`, `azure_client_secret`, and `azure_tenant_id` in `config.json`. The service principal needs Contributor role on the subscription. If left blank, ACI proxy is disabled.

### Spray Settings

These can be set in `config.json` as defaults, or overridden per-run with CLI flags:

| Setting | CLI Flag | Default | Description |
|---------|----------|---------|-------------|
| `delay` | `--delay` | 30 | Seconds to wait between spray attempts per user. Higher = slower but safer. |
| `jitter` | `--jitter` | 5 | Random 0 to N seconds added to each delay. Prevents predictable timing patterns. |
| `shuffle` | `--shuffle` | standard | How user/password pairs are ordered. `standard` groups by password round, `aggressive` fully randomizes all pairs. |
| `lockout_threshold` | `--lockout-threshold` | 10 | Stop spraying entirely after this many consecutive account lockouts. |
| `lockout_cooldown` | `--lockout-cooldown` | 1800 | Seconds to skip a locked-out user before retrying them (default 30 minutes). |
| - | `--resume` | off | Resume from database state, skipping already-attempted pairs. |

### Quiet Mode

Add `-q` to suppress per-attempt output and show only progress and actionable results:

```bash
python3 cloudspray.py -q spray -d example.com -u users.txt -P 'password'
```

Without `-q`, all attempt results are shown including invalid passwords and not-found users.

## Enumeration Methods

| Method | Auth Required | Noise Level | Technique |
|--------|:---:|:---:|-----------|
| `msol` | No | Low | POST to `GetCredentialType` endpoint, checks if email exists via `IfExistsResult` field |
| `onedrive` | No | Low | HEAD request to user's SharePoint personal site, 403 means exists, 404 means not |
| `teams` | Yes (sacrificial) | Medium | Teams user search API, requires a valid account in any tenant |
| `login` | No | **High** | ROPC auth with fake password, generates sign-in events in Azure AD logs |

**Recommendation:** Start with `msol`. It's the most reliable and doesn't generate login events. Use `onedrive` to cross-validate if needed. Avoid `login` unless other methods fail because it creates audit log entries.

**Note on OneDrive:** This method only works when the tenant's SharePoint personal site URL resolves (e.g. `example-my.sharepoint.com`). Some organizations use different tenant naming or don't provision OneDrive for all users. If you get DNS resolution errors, switch to `msol`.

## Okta Spraying

For organizations that federate to Okta, use the dedicated Okta sprayer:

```bash
python3 cloudspray.py okta-spray -d example.com -u users.txt -P 'Spring2026!'
```

CloudSpray auto-discovers the Okta URL from DNS if `--okta-url` is not specified. You can also provide it explicitly:

```bash
python3 cloudspray.py okta-spray -d example.com -u users.txt -P 'Spring2026!' --okta-url https://example.okta.com
```

Okta spraying uses more conservative defaults (60s delay, 15s jitter) because Okta's rate limiting is more aggressive than Azure AD's.

## Spray Result Classification

CloudSpray classifies Azure AD responses by AADSTS error codes:

| Result | AADSTS Code | Meaning |
|--------|:-----------:|---------|
| `success` | - | Valid credentials, no MFA |
| `valid_password_mfa_required` | 50076 | Password is correct, MFA blocks sign-in |
| `valid_password_mfa_enrollment` | 50079 | Password is correct, user hasn't enrolled in MFA yet |
| `valid_password_ca_blocked` | 53003 | Password is correct, Conditional Access policy blocks |
| `valid_password_expired` | 50055 | Password is correct but expired |
| `invalid_password` | 50126 | Wrong password |
| `account_locked` | 50053 | Account locked (Smart Lockout or admin) |
| `account_disabled` | 50057 | Account exists but is disabled |
| `user_not_found` | 50034 | Email doesn't exist in the tenant |
| `rate_limited` | 50196 | Azure AD is throttling requests |

**Key insight:** Results like `mfa_required`, `ca_blocked`, and `expired` all confirm the password is correct. The account is just protected by additional controls.

## Lockout Safety

CloudSpray has two layers of lockout protection:

1. **Per-user cooldown** - When an account returns "locked" (50053), that user is skipped for 30 minutes (configurable via `--lockout-cooldown`). Other users continue normally. After cooldown expires, the user is automatically retried.

2. **Consecutive lockout circuit breaker** - If 10 accounts lock out in a row without any non-lockout result in between, the entire spray hard stops. This prevents cascading lockouts across the tenant. The counter resets on any non-lockout result (invalid password, user not found, etc.). The breaker applies to every attempt, including pairs being retried after a cooldown.

### What happens to pairs that never get attempted

Deferred pairs are retried once their user clears cooldown. If the queue drains while accounts are
still locked, CloudSpray waits for the next account to clear — but only up to two minutes, since
the cooldown defaults to 30 minutes and blocking for the full window would hang the run with no
output.

Anything still unattempted when the run ends is reported explicitly: how many pairs, which users,
and why (still cooling down, or cut off by the circuit breaker), along with a reminder to re-run
with `--resume`. A pair that was never tested must never be mistaken for one with no valid
password, so this accounting is deliberately loud. Pairs whose account stays locked across two
cooldown cycles are given up on and named.

## IP Rotation

Traditional password spraying sends all requests from one IP. CloudSpray supports two proxy backends for IP rotation.

**Rotation is the intended default.** Any run that ends up without it — `--proxy-backend none`, or
`auto` finding no AWS/Azure credentials in `config.json` — prints a warning stating that requests
will leave from this host's public IP, that attempts will be attributable to you, and that
IP-based lockout or blocking will hit your address directly. Spraying from your own IP by accident
should not be something you discover later from the target's logs.

### AWS API Gateway (Fireprox)

Creates ephemeral AWS API Gateway endpoints that act as reverse proxies:

1. CloudSpray creates API Gateway REST APIs in multiple AWS regions
2. Each gateway has an `HTTP_PROXY` integration pointing at `login.microsoftonline.com`
3. When CloudSpray sends a request to the gateway, AWS forwards it to Microsoft from a **different IP** each time
4. Microsoft sees requests from many different AWS IPs, making IP-based blocking ineffective

Gateways are round-robined per request and automatically torn down when the operation completes (or on Ctrl+C).

#### X-Forwarded-For

Rotating the source IP is only half the job. Left to its own devices, API Gateway appends the
caller's real IP to `X-Forwarded-For` before handing the request to the backend — so the target
sees straight through the proxy even though the TCP connection comes from AWS.

Each gateway is therefore built with a request-parameter mapping that overwrites `X-Forwarded-For`
from a client-supplied `X-My-X-Forwarded-For` header, and the session sends that header on every
proxied request. The value is empty by default, which suppresses the operator's address without
impersonating some unrelated third party. `AWSGatewayProvider(..., forwarded_for="203.0.113.7")`
sets it explicitly if a specific value is ever wanted.

#### Health checks

After deployment each gateway is probed through the proxy. A response carrying the
`x-amzn-ErrorType` header was generated by API Gateway itself and never reached the backend, so it
counts as a failure — checking only for "status below 500" would pass a gateway whose integration
is misconfigured, since API Gateway answers unroutable requests with its own `403`.

If gateway creation fails in some regions but not others, the run continues with a warning naming
the failed regions, so reduced IP diversity is visible rather than silent.

#### AWS Permissions Required

The IAM user needs `AmazonAPIGatewayAdministrator` or a custom policy with:
- `apigateway:POST` (create APIs, resources, methods, integrations, deployments)
- `apigateway:GET` (list resources)
- `apigateway:DELETE` (teardown)

### Azure Container Instances

Deploys tinyproxy containers across Azure regions, each with a unique public IP:

1. CloudSpray creates lightweight proxy containers in multiple Azure regions
2. Each container gets its own public IP on port 8888
3. Requests are round-robin distributed across all container IPs
4. Traffic originates from Azure IP space, blending in with legitimate M365 traffic

Containers are automatically cleaned up on teardown. Tinyproxy is configured with an IP allowlist restricting access to the operator's public IP, preventing abuse as an open relay. This backend requires Azure service principal credentials in `config.json`.

## Post-Exploitation

After finding valid credentials, the `post` command provides three capabilities:

### FOCI Token Exchange (`--foci`)

Microsoft's Family of Client IDs (FOCI) program allows refresh tokens from one app to be exchanged for tokens targeting any other FOCI member app. CloudSpray authenticates via one client ID, then iterates through all 27 FOCI member apps to mint access tokens for Teams, OneDrive, SharePoint, Outlook, and more.

### Conditional Access Probing (`--ca-probe`)

Takes accounts with MFA or CA-blocked status and tests every combination of client ID and resource endpoint looking for policy gaps. Organizations often only secure common scenarios. An unexpected success on an unusual client ID means there's an exploitable gap in the Conditional Access policy.

### Data Access Check (`--exfil`)

Read-only proof-of-impact using Microsoft Graph API:
- **OneDrive:** Lists files in the user's drive
- **Email:** Retrieves recent messages
- **Teams:** Enumerates joined teams and channels

All read-only. Designed to demonstrate access scope for reporting, not exfiltrate data.

## State & Resume

All operations are persisted to a SQLite database (`cloudspray.db` by default). This enables:

- **Resume after interruption** - The `--resume` flag skips already-attempted credential pairs
- **Cross-command continuity** - Enum results, spray attempts, valid credentials, and tokens are all stored in one DB
- **Post-exploitation** - The `post` command reads valid credentials from the DB automatically
- **Direct queries** - You can inspect raw results anytime with `sqlite3`:

```bash
# See all spray attempts
sqlite3 -header -column cloudspray.db "SELECT username, password, result, timestamp FROM spray_attempts ORDER BY timestamp"

# Just the hits (valid passwords, MFA, CA blocked, etc.)
sqlite3 -header -column cloudspray.db "SELECT * FROM spray_attempts WHERE result NOT IN ('invalid_password', 'user_not_found')"

# Full request details (client ID, endpoint, user-agent, proxy URL)
sqlite3 -header -column cloudspray.db "SELECT * FROM spray_attempts LIMIT 10"
```

## Security Notes

- The SQLite database (`cloudspray.db`) stores credentials and tokens in plaintext. File permissions are automatically set to `0600` (owner read/write only) on creation. Treat this file as sensitive.
- JSON reports redact passwords in the spray log by default. Use `--no-redact` only when you need the full data.
- `.gitignore` covers everything an engagement produces or consumes — the database, JSON and CSV reports, logs, and user/name/password/email/target list files — so engagement data cannot be committed by a stray `git add .`. `config.json.example` is the only JSON kept in the repo.
- ACI proxy containers are restricted to the operator's IP via tinyproxy allowlist configuration.
- Dependencies are pinned to exact versions in `requirements.txt` for reproducible builds.

## Development

```bash
# Install dev dependencies (includes pytest)
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v
```

## Legal Disclaimer

This tool is designed for **authorized penetration testing and security assessments only**. Unauthorized access to computer systems is illegal. Always obtain written authorization before testing any system you don't own. The authors are not responsible for misuse of this tool.
