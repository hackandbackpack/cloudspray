# CloudSpray

M365 password sprayer and user enumerator with Fireprox proxy rotation for authorized penetration testing.

## What It Does

CloudSpray automates two common steps in M365 security assessments:

1. **User Enumeration** — Identifies which email addresses correspond to valid Azure AD accounts using multiple techniques (no authentication required for most methods)
2. **Password Spraying** — Tests discovered accounts against a password list, classifying responses to identify valid credentials, MFA enforcement, account lockouts, and more

All requests can be routed through **AWS API Gateway (Fireprox)** for IP rotation, making it difficult for Microsoft to block or rate-limit the source.

## Project Structure

```
cloudspray/                  # repo root
├── cloudspray.py            # entry point — run this
├── .env.example             # AWS credentials template
├── requirements.txt
└── cloudspray/              # package
    ├── cli.py               # Click CLI commands
    ├── settings.py           # Config loading from .env
    ├── utils.py             # File I/O, logging, helpers
    ├── enumerators/         # User enumeration methods
    ├── spray/               # Password spray engine
    ├── proxy/               # Fireprox IP rotation
    ├── post/                # Post-exploitation modules
    ├── reporting/           # JSON/CSV output
    ├── state/               # SQLite persistence
    └── constants/           # Microsoft client IDs, endpoints, error codes
```

## Installation

```bash
git clone https://github.com/hackandbackpack/cloudspray.git
cd cloudspray

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### 1. Enumerate Users

```bash
# MSOL method (recommended — reliable, no auth required)
python3 cloudspray.py enum -d example.com -u userlist.txt -m msol -o valid-users.txt

# OneDrive method (passive, but tenant-dependent)
python3 cloudspray.py enum -d example.com -u userlist.txt -m onedrive -o valid-users.txt
```

### 2. Password Spray

```bash
# Single password
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!'

# Password list
python3 cloudspray.py spray -d example.com -u valid-users.txt -p passwords.txt
```

### 3. With Fireprox (Recommended)

Set up AWS credentials for IP rotation:

```bash
cp .env.example .env
```

Edit `.env` and fill in your AWS access key and secret key. Then run normally — CloudSpray automatically detects the credentials and enables Fireprox:

```bash
# Enum through Fireprox
python3 cloudspray.py enum -d example.com -u userlist.txt -m msol -o valid-users.txt

# Spray through Fireprox
python3 cloudspray.py spray -d example.com -u valid-users.txt -P 'Spring2026!'
```

### 4. Post-Exploitation (after finding valid credentials)

```bash
# FOCI token exchange — test access across Microsoft services
python3 cloudspray.py post --foci

# Probe for Conditional Access gaps
python3 cloudspray.py post --ca-probe

# Check Graph API data access
python3 cloudspray.py post --exfil
```

### 5. Reporting

```bash
python3 cloudspray.py report -f json -o results.json
python3 cloudspray.py report -f csv -o results.csv
```

## Configuration

AWS credentials are the only file-based config. Everything else is CLI flags.

### AWS Setup (.env)

```bash
cp .env.example .env
```

Fill in your IAM credentials. See `.env.example` for details on required permissions.

### CLI Flags

Spray settings are all CLI flags with sensible defaults:

```bash
python3 cloudspray.py spray -d example.com -u users.txt -P 'password' \
    --delay 60 --jitter 10 --lockout-threshold 5 --lockout-cooldown 3600
```

| Flag | Default | Description |
|------|---------|-------------|
| `--delay` | 30 | Seconds between attempts per user |
| `--jitter` | 5 | Random 0-N seconds added to delay |
| `--lockout-threshold` | 10 | Consecutive lockouts before hard stop |
| `--lockout-cooldown` | 1800 | Per-user cooldown after lockout (seconds) |
| `--shuffle` | standard | Pair ordering: "standard" or "aggressive" |
| `--resume` | off | Resume from database state |

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

1. **Per-user cooldown** — When an account returns "locked" (50053), that user is skipped for 30 minutes (configurable via `--lockout-cooldown`). Other users continue normally. After cooldown expires, the user is automatically retried.

2. **Consecutive lockout circuit breaker** — If 10 accounts lock out in a row without any non-lockout result in between, the entire spray hard stops. This prevents cascading lockouts across the tenant. The counter resets on any non-lockout result (invalid password, user not found, etc.).

## How Fireprox Works

Traditional password spraying sends all requests from one IP. Microsoft can easily detect and block this. Fireprox solves this by creating AWS API Gateway endpoints that act as reverse proxies:

1. CloudSpray creates API Gateway REST APIs in multiple AWS regions
2. Each gateway has an `HTTP_PROXY` integration pointing at `login.microsoftonline.com`
3. When CloudSpray sends a request to the gateway, AWS forwards it to Microsoft from a **different IP** each time (from AWS's pool of thousands of IPs per region)
4. Microsoft sees requests from many different AWS IPs, making IP-based blocking ineffective

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

## Legal Disclaimer

This tool is designed for **authorized penetration testing and security assessments only**. Unauthorized access to computer systems is illegal. Always obtain written authorization before testing any system you don't own. The authors are not responsible for misuse of this tool.
