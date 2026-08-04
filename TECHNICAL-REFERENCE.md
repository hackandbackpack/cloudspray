# CloudSpray - Technical Reference

Package layout and the non-obvious behaviour behind it. See `README.md` for operator-facing usage.

## Module map

```
cloudspray.py              entry point
cloudspray/
  cli.py                   Click commands; _build_proxy_session wires rotation
  settings.py              config.json loading, CLI override precedence
  utils.py                 file I/O, normalize_email, random_suffix
  constants/
    client_ids.py          47 Microsoft first-party app IDs (public knowledge)
    endpoints.py           resource endpoints for scope construction
    error_codes.py         AADSTS -> AuthResult mapping
    user_agents.py         UA pool for per-attempt rotation
  enumerators/             msol, onedrive, teams, login
  spray/
    auth.py                Authenticator - MSAL ROPC, one attempt per call
    okta_auth.py           Okta /api/v1/authn sprayer
    classifier.py          response -> AuthResult
    shuffle.py             standard (password-round) and aggressive orderings
    engine.py              queue, lockout cooldown, circuit breaker
  proxy/
    base.py                ProxyProvider interface
    aws_gateway.py         Fireprox - API Gateway REST APIs
    azure_aci.py           tinyproxy containers
    session.py             FireproxSession - URL rewriting
    manager.py             multi-provider round-robin, teardown, rollback
    proxy_list.py          static proxy list provider
  post/                    ca_probe, exfil, tokens (FOCI)
  recon/                   discovery, footprint, dns_utils
  reporting/               console, json_report, csv_report
  state/                   db (SQLite), models
```

## Proxy rotation

Two mechanically different backends behind one interface:

- **AWS (Fireprox)** is a *reverse* proxy. API Gateway does not read proxy headers, so
  `FireproxSession` overrides `requests.Session.request` and rewrites the URL host to the gateway
  invoke URL. `provider.get_proxy_url()` is called per request, so rotation is per request, not per
  session.
- **Azure ACI** is a *forward* proxy, so it uses an ordinary `proxies` dict.

`ProxyManager.get_session()` only serves the forward-proxy model. AWS callers construct
`FireproxSession` directly. `ProxyManager` is still used for AWS to get context-managed teardown
and setup rollback.

Each command proxies its own target host, not a single global one: `enum` picks from
`_ENUM_TARGET_HOSTS` per method and computes `<tenant>-my.sharepoint.com` for OneDrive,
`okta-spray` passes the resolved Okta host, `spray`/`format` use `login.microsoftonline.com`. The
session only rewrites URLs matching its configured `target_host`; anything else passes through
direct.

### X-Forwarded-For (load-bearing)

API Gateway appends the caller's real IP to `X-Forwarded-For` before calling the backend. Rotating
the TCP source is therefore not sufficient on its own — the operator's address still reaches the
target in a header.

Each gateway maps `integration.request.header.X-Forwarded-For` from
`method.request.header.X-My-X-Forwarded-For`, declared on the method as an optional request
parameter. `FireproxSession` sends `X-My-X-Forwarded-For` on every rewritten request, defaulting to
empty (suppress rather than impersonate). Both halves are required: the mapping without the header
has nothing to substitute, and the header without the mapping is ignored.

`FireproxSession.forwarded_for` falls back to `provider.forwarded_for` when not passed explicitly,
and header dicts supplied by callers are copied rather than mutated (MSAL reuses them).

### Gateway construction

Per region: `create_rest_api` (REGIONAL) → `{proxy+}` greedy resource → `ANY` method →
`HTTP_PROXY` integration to `<target>/{proxy}` → **also** an `ANY` method and integration on the
root resource → `create_deployment(stageName="proxy")`.

The root resource matters for observability: without a method on `/`, a request to the bare invoke
URL is answered by API Gateway rather than the backend, which makes a working gateway
indistinguishable from a broken one.

`api_id` is recorded in `_api_ids` immediately after creation so teardown works even if a later
setup step fails. Per-region failures are collected in `_failed_regions` and surfaced as a warning;
setup only raises when *no* region succeeded.

### Health check

Probes through the proxy and rejects any response carrying `x-amzn-ErrorType`, which API Gateway
stamps on responses it generates itself. A status-only check would pass a misconfigured integration,
because API Gateway answers unroutable requests with its own `403`.

Public accessors: `gateway_count`, `failed_regions`, `forwarded_for`.

## Spray engine

`SprayEngine.run` builds pairs (`standard_shuffle` or `aggressive_shuffle`), optionally filters
already-attempted pairs for `--resume`, preloads confirmed users from the DB, then loops:

```
while queue or deferred:
    _drain(...)                      # attempts pairs; returns True if breaker tripped
    promote deferred pairs whose cooldown expired
    otherwise wait (bounded) for the next unlock, or stop
_report_unfinished(...)
```

`_drain` is the **only** place a pair is attempted. This is deliberate. The previous
implementation had a second, trimmed copy of the loop for lockout retries that had lost the circuit
breaker and the rate-limit re-queue, so retried pairs — the ones most likely to lock again — ran
with no safety mechanisms and rate-limited pairs were silently discarded.

Ordering note: both shuffle modes randomize, so tests that depend on attempt order must exercise
`_handle_result` directly rather than driving `run`.

### Counters and bounds

| Name | Value | Purpose |
|---|---|---|
| `RATE_LIMIT_SLEEP_SECONDS` | 60 | Sleep before re-queueing an AADSTS50196 pair |
| `MAX_LOCKOUT_DEFERRALS` | 2 | Cooldown cycles a pair may wait before being abandoned; also caps waiting rounds |
| `MAX_COOLDOWN_WAIT_SECONDS` | 120 | Ceiling on idle waiting for a cooldown to clear |

The wait is floored at 1 second. A sub-second remainder previously produced a stream of near-zero
sleeps with duplicate log lines — a spin loop that burned real CPU. Both the floor and the
`wait_rounds` cap exist to make that impossible even if the clock does not advance as expected.

`_handle_result` returns after incrementing `_consecutive_lockouts` on `ACCOUNT_LOCKED`. Falling
through to the trailing reset would zero the counter immediately and the breaker could never fire.

### Accounting

- Progress total shrinks (`_drop_pair`) only for pairs that will never be attempted: user already
  confirmed, or abandoned after repeated lockouts. Deferred pairs keep their slot, since they are
  postponed rather than dropped.
- `_report_unfinished` names every unattempted pair and why. Silence is the hazard: a user list
  believed fully sprayed will not be re-run, and an untested account is indistinguishable from one
  with no valid password.

## Authentication

`Authenticator` builds `msal.PublicClientApplication(client_id, authority, http_client=session)`,
cached per client ID so OpenID discovery happens once rather than per attempt. Passing the session
as `http_client` is what routes MSAL traffic through Fireprox — `Session.post()` dispatches through
the overridden `request()`, so the rewrite applies to discovery and token calls alike.

Each attempt randomizes client ID, resource endpoint, and User-Agent. `{tenant}` in SharePoint
endpoints is replaced with the first label of the domain. `proxy_used` is read from
`session.last_proxy_url` after the MSAL call and persisted per attempt.

Results treated as password-confirmed: `SUCCESS`, `VALID_PASSWORD_MFA_REQUIRED`,
`VALID_PASSWORD_MFA_ENROLLMENT`, `VALID_PASSWORD_CA_BLOCKED`, `VALID_PASSWORD_EXPIRED`. Any of
these adds the user to `_confirmed_users` and stops further passwords for them.

## State

SQLite via `StateDB`, chmod `0600` on creation, holding spray attempts, valid credentials, locked
accounts, enum results, and tokens. `filter_unattempted_pairs` backs `--resume`, which is also the
documented recovery path for pairs left unattempted by lockouts or the circuit breaker.

## Repository hygiene

`.gitignore` excludes everything an engagement touches: `*.db`, `*.sqlite`, `*.json` (with
`!config.json.example`), `*.csv`, `*.log`, and user/name/password/email/target `.txt` lists. JSON is
covered because reports carry usernames, tokens, and plaintext passwords under `--no-redact`. This
repo is public; a stray `git add .` mid-engagement is the failure mode being designed against.

## Known limitations

- `ProxyManager.get_session()` does not support the Fireprox model; AWS callers must use
  `FireproxSession`.
- Azure ACI wiring in `cli.py` patches `session.request` on the instance rather than subclassing.
- The `login` enumeration method generates Azure AD sign-in events; `msol` is preferred.
- Unreviewed for correctness at the time of writing: `state/db.py`, `azure_aci.py`, the four
  enumerators, `post/`, `recon/`, and `reporting/`.
