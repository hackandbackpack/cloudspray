import click

from cloudspray.config import load_config
from cloudspray.reporting.console import ConsoleReporter
from cloudspray.state.db import StateDB
from cloudspray.utils import setup_logging


class MutuallyExclusive(click.Option):
    """Click option that enforces mutual exclusivity with another option."""

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
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
    """CloudSpray - Azure AD password sprayer and enumerator."""
    ctx.ensure_object(dict)

    cfg = load_config(config)
    ctx.obj["config"] = cfg
    ctx.obj["db_path"] = db
    ctx.obj["verbose"] = verbose

    log_level = "DEBUG" if verbose else "INFO"
    ctx.obj["logger"] = setup_logging(level=log_level)

    ctx.obj["reporter"] = ConsoleReporter(verbose=verbose)


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

    with StateDB(ctx.obj["db_path"]) as db:
        reporter.info(f"Enumeration starting: domain={domain}, method={method}")
        reporter.info(f"User list: {users}")
        if output:
            reporter.info(f"Output file: {output}")
        reporter.info("Enumeration engine not yet implemented.")


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
@click.option("--delay", type=int, default=None, help="Seconds between attempts per user.")
@click.option("--jitter", type=int, default=None, help="Random jitter range in seconds.")
@click.option("--lockout-threshold", type=int, default=None, help="Pause after N lockouts.")
@click.option("--lockout-pause", type=int, default=None, help="Pause duration in seconds on lockout.")
@click.option(
    "--shuffle",
    type=click.Choice(["standard", "aggressive"], case_sensitive=False),
    default=None,
    help="Shuffle mode for spray ordering.",
)
@click.option("--resume", is_flag=True, default=False, help="Resume from database state.")
@click.pass_context
def spray_cmd(ctx, domain, users, passwords, password, delay, jitter,
              lockout_threshold, lockout_pause, shuffle, resume):
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
    if lockout_pause is not None:
        cfg.spray.lockout_pause = lockout_pause
    if shuffle is not None:
        cfg.spray.shuffle_mode = shuffle

    with StateDB(ctx.obj["db_path"]) as db:
        reporter.info(f"Spray engine starting: domain={domain}")
        reporter.info(f"User list: {users}")
        reporter.info(
            f"Delay={cfg.spray.delay}s, Jitter={cfg.spray.jitter}s, "
            f"Shuffle={cfg.spray.shuffle_mode}"
        )
        if resume:
            attempted = db.get_attempted_pairs()
            reporter.info(f"Resuming: {len(attempted)} attempts already recorded.")
        reporter.info("Spray engine not yet implemented.")


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

    with StateDB(ctx.obj["db_path"]) as db:
        creds = db.get_valid_credentials()
        if not creds:
            reporter.error("No valid credentials in database. Run 'spray' first.")
            raise SystemExit(1)

        reporter.info(f"Post-exploitation: {len(creds)} valid credential(s) available.")
        if user:
            reporter.info(f"Targeting user: {user}")
        if foci:
            reporter.info("FOCI token exchange not yet implemented.")
        if ca_probe:
            reporter.info("CA policy probing not yet implemented.")
        if exfil:
            reporter.info("Data exfiltration check not yet implemented.")


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

    with StateDB(ctx.obj["db_path"]) as db:
        creds = db.get_valid_credentials()
        reporter.info(f"Generating {output_format.upper()} report: {output}")
        reporter.info(f"Found {len(creds)} valid credential(s).")
        reporter.info("Report generation not yet implemented.")
