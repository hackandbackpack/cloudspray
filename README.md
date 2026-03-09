# CloudSpray

M365 password sprayer and user enumerator with Fireprox proxy rotation for authorized penetration testing.

## What It Does

CloudSpray automates two common steps in M365 security assessments:

1. **User Enumeration** — Identifies which email addresses correspond to valid Azure AD accounts using multiple techniques (no authentication required for most methods)
2. **Password Spraying** — Tests discovered accounts against a password list, classifying responses to identify valid credentials, MFA enforcement, account lockouts, and more

All requests can be routed through **AWS API Gateway (Fireprox)** for IP rotation, making it difficult for Microsoft to block or rate-limit the source.

## Architecture

```
cloudspray/
├── cli.py              # Click CLI — entry point for all commands
├── config.py           # YAML config with dataclass defaults
├── utils.py            # File reading, email normalization, logging
├── enum/               # User enumeration methods
│   ├── onedrive.py     # SharePoint personal site probing (403=exists, 404=not)
│   ├── msol.py         # GetCredentialType API (IfExistsResult field)
│   ├── teams.py        # Teams user search (requires sacrificial account)
│   └── login.py        # ROPC auth with fake password (noisy — generates logs)
├── spray/              # Password spray engine
│   ├── auth.py         # MSAL ROPC auth with client ID/endpoint/UA rotation
│   ├── engine.py       # Core loop with per-user lockout cooldown, circuit breaker
│   ├── classifier.py   # Maps AADSTS error codes to result categories
│   └── shuffle.py      # Credential pair ordering (standard vs aggressive)
├── proxy/              # IP rotation providers
│   ├── session.py      # FireproxSession — URL-rewriting requests.Session
│   ├── aws_gateway.py  # AWS API Gateway (Fireprox) — multi-region, auto-teardown
│   ├── azure_aci.py    # Azure Container Instance proxy (alternative)
│   ├── proxy_list.py   # Static proxy list from file
│   ├── manager.py      # ProxyManager — round-robin, failover, health checks
│   └── base.py         # Abstract ProxyProvider interface
├── post/               # Post-exploitation modules
│   ├── tokens.py       # FOCI token exchange across Microsoft services
│   ├── ca_probe.py     # Conditional Access policy gap detection
│   └── exfil.py        # Graph API data access checks
├── state/              # SQLite state persistence
│   ├── db.py           # StateDB — thread-safe CRUD for all tables
│   └── models.py       # Dataclasses for attempts, credentials, tokens
├── reporting/          # Output generation
│   ├── console.py      # Rich-powered terminal output with progress bars
│   ├── json_report.py  # JSON report export
│   └── csv_report.py   # CSV report export
└── constants/          # Static data
    ├── client_ids.py   # 30+ Microsoft first-party OAuth client IDs
    ├── endpoints.py    # 12 Microsoft resource endpoints
    ├── error_codes.py  # AADSTS code → AuthResult enum mapping
    └── user_agents.py  # Browser user agent strings for rotation
```

## Installation

```bash
# Clone the repository
git clone https://github.com/hackandbackpack/cloudspray.git
cd cloudspray

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### 1. Enumerate Users

Find which email addresses are valid Azure AD accounts:

```bash
# MSOL method (recommended — reliable, no auth required)
python -m cloudspray enum -d example.com -u userlist.txt -m msol -o valid-users.txt

# OneDrive method (passive, but tenant-dependent)
python -m cloudspray enum -d example.com -u userlist.txt -m onedrive -o valid-users.txt
```

### 2. Password Spray

Test valid users against passwords:

```bash
# Single password
python -m cloudspray spray -d example.com -u valid-users.txt -P 'Spring2026!'

# Password list
python -m cloudspray spray -d example.com -u valid-users.txt -p passwords.txt
```

### 3. With Fireprox (Recommended)

Route all traffic through AWS API Gateway for IP rotation:

```bash
# Create config with AWS credentials
cat > config.yaml << 'EOF'
proxy:
  aws_gateway:
    enabled: true
    access_key: "YOUR_AWS_ACCESS_KEY"
    secret_key: "YOUR_AWS_SECRET_KEY"
    regions:
      - us-east-1
      - us-west-2
      - eu-west-1
EOF

# Enum through Fireprox
python -m cloudspray -c config.yaml enum -d example.com -u userlist.txt -m msol -o valid-users.txt

# Spray through Fireprox
python -m cloudspray -c config.yaml spray -d example.com -u valid-users.txt -P 'Spring2026!'
```

### 4. Post-Exploitation (after finding valid credentials)

```bash
# FOCI token exchange — test access across Microsoft services
python -m cloudspray post --foci

# Probe for Conditional Access gaps
python -m cloudspray post --ca-probe

# Check Graph API data access
python -m cloudspray post --exfil
```

### 5. Reporting

```bash
python -m cloudspray report -f json -o results.json
python -m cloudspray report -f csv -o results.csv
```

## Configuration

CloudSpray uses YAML config files merged with built-in defaults. You only need to specify values you want to override.

### Full Config Reference

```yaml
target:
  domain: example.com          # Target domain

spray:
  delay: 30                    # Seconds between attempts per user
  jitter: 5                    # Random jitter added to delay (0-N seconds)
  lockout_threshold: 10        # Hard stop after N consecutive lockouts
  lockout_cooldown: 1800       # Per-user lockout cooldown in seconds (30 min)
  shuffle_mode: standard       # Pair ordering: "standard" or "aggressive"

proxy:
  aws_gateway:
    enabled: false
    access_key: ""
    secret_key: ""
    regions:                   # More regions = more IP diversity
      - us-east-1
      - us-west-2
      - eu-west-1

enum:
  teams_user: ""               # Sacrificial account for Teams enum
  teams_pass: ""
```

### CLI Overrides

Most spray settings can be overridden via CLI flags:

```bash
python -m cloudspray spray -d example.com -u users.txt -P 'password' \
    --delay 60 --jitter 10 --lockout-threshold 5 --lockout-cooldown 3600
```

## Enumeration Methods

| Method | Auth Required | Noise Level | Technique |
|--------|:---:|:---:|-----------|
| `msol` | No | Low | POST to `GetCredentialType` endpoint — checks if email exists via `IfExistsResult` field |
| `onedrive` | No | Low | HEAD request to user's SharePoint personal site — 403 means exists, 404 means not |
| `teams` | Yes (sacrificial) | Medium | Teams user search API — requires a valid account in any tenant |
| `login` | No | **High** | ROPC auth with fake password — generates sign-in events in Azure AD logs |

**Recommendation:** Start with `msol`. It's the most reliable and doesn't generate login events. Use `onedrive` to cross-validate if needed. Avoid `login` unless other methods fail — it creates audit log entries.

## Spray Result Classification

CloudSpray classifies Azure AD responses by AADSTS error codes:

| Result | AADSTS Code | Meaning |
|--------|:-----------:|---------|
| `success` | — | Valid credentials, no MFA |
| `valid_password_mfa_required` | 50076 | Password is correct, MFA blocks sign-in |
| `valid_password_mfa_enrollment` | 50079 | Password is correct, user hasn't enrolled in MFA yet |
| `valid_password_ca_blocked` | 53003 | Password is correct, Conditional Access policy blocks |
| `valid_password_expired` | 50055 | Password is correct but expired |
| `invalid_password` | 50126 | Wrong password |
| `account_locked` | 50053 | Account locked (Smart Lockout or admin) |
| `account_disabled` | 50057 | Account exists but is disabled |
| `user_not_found` | 50034 | Email doesn't exist in the tenant |
| `rate_limited` | 50196 | Azure AD is throttling requests |

**Key insight:** Results like `mfa_required`, `ca_blocked`, and `expired` all confirm the password is correct — the account is just protected by additional controls.

## Lockout Safety

CloudSpray has two layers of lockout protection:

1. **Per-user cooldown** — When an account returns "locked" (50053), that user is skipped for 30 minutes (configurable via `lockout_cooldown`). Other users continue normally. After cooldown expires, the user is automatically retried.

2. **Consecutive lockout circuit breaker** — If 10 accounts lock out in a row without any non-lockout result in between, the entire spray hard stops. This prevents cascading lockouts across the tenant. The counter resets on any non-lockout result (invalid password, user not found, etc.).

## How Fireprox Works

Traditional password spraying sends all requests from one IP. Microsoft can easily detect and block this. Fireprox solves this by creating AWS API Gateway endpoints that act as reverse proxies:

1. CloudSpray creates API Gateway REST APIs in multiple AWS regions
2. Each gateway has an `HTTP_PROXY` integration pointing at `login.microsoftonline.com`
3. When CloudSpray sends a request to the gateway, AWS forwards it to Microsoft from a **different IP** each time (from AWS's pool of thousands of IPs per region)
4. Microsoft sees requests from many different AWS IPs, making IP-based blocking ineffective

CloudSpray's `FireproxSession` handles this transparently by rewriting request URLs:

```
Original:  POST https://login.microsoftonline.com/common/GetCredentialType
Rewritten: POST https://abc123.execute-api.us-east-1.amazonaws.com/proxy/common/GetCredentialType
```

Gateways are automatically torn down when the operation completes (or on Ctrl+C).

### AWS Permissions Required

The IAM user needs `AmazonAPIGatewayAdministrator` or a custom policy with:
- `apigateway:POST` (create APIs, resources, methods, integrations, deployments)
- `apigateway:GET` (list resources)
- `apigateway:DELETE` (teardown)

## State & Resume

All operations are persisted to a SQLite database (`cloudspray.db` by default). This enables:

- **Resume after interruption** — The `--resume` flag skips already-attempted credential pairs
- **Cross-command continuity** — Enum results, spray attempts, valid credentials, and tokens are all stored in one DB
- **Post-exploitation** — The `post` command reads valid credentials from the DB automatically

## Anti-Fingerprinting

Each spray attempt randomizes:
- **Client ID** — Chosen from 30+ Microsoft first-party OAuth application IDs
- **Resource endpoint** — Randomly selected from 12 Microsoft services (Graph, Exchange, SharePoint, etc.)
- **User-Agent** — Rotated from a list of common browser strings

This makes each request look like a different application from a different browser, reducing pattern-based detection.

## Legal Disclaimer

This tool is designed for **authorized penetration testing and security assessments only**. Unauthorized access to computer systems is illegal. Always obtain written authorization before testing any system you don't own. The authors are not responsible for misuse of this tool.
