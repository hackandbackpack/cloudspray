from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from cloudspray import __version__
from cloudspray.constants.error_codes import AuthResult
from cloudspray.state.models import SprayAttempt, ValidCredential

BANNER_ART = r"""
   _____ _                 _  _____
  / ____| |               | |/ ____|
 | |    | | ___  _   _  __| | (___  _ __  _ __ __ _ _   _
 | |    | |/ _ \| | | |/ _` |\___ \| '_ \| '__/ _` | | | |
 | |____| | (_) | |_| | (_| |____) | |_) | | | (_| | |_| |
  \_____|_|\___/ \__,_|\__,_|_____/| .__/|_|  \__,_|\__, |
                                   | |                __/ |
                                   |_|               |___/
"""


class ConsoleReporter:
    """Rich-powered console output for all CloudSpray modules."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.console = Console()

    def banner(self) -> None:
        """Print the CloudSpray ASCII banner with version."""
        self.console.print(Text(BANNER_ART, style="bold cyan"))
        self.console.print(
            f"  [bold white]v{__version__}[/bold white]  |  "
            "[dim]Azure AD Password Sprayer & Enumerator[/dim]\n"
        )

    def start_spray(self, total_attempts: int) -> tuple[Progress, TaskID]:
        """Create and start a Rich progress bar for spray operations."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
        )
        progress.start()
        task_id = progress.add_task("Spraying...", total=total_attempts)
        return progress, task_id

    def update_progress(self, progress: Progress, task_id: TaskID, advance: int = 1) -> None:
        """Advance a progress bar task."""
        progress.update(task_id, advance=advance)

    def print_result(self, attempt: SprayAttempt) -> None:
        """Print a color-coded single-line spray result."""
        result = attempt.result
        label = f"{attempt.username}:{attempt.password}"

        if result == AuthResult.SUCCESS:
            self.console.print(f"[bold green][+][/bold green] {label} - [green]SUCCESS[/green]")
            return

        if result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT:
            self.console.print(
                f"[bold red][!!][/bold red] {label} - "
                "[bold red]MFA ENROLLMENT REQUIRED (50079)[/bold red]"
            )
            return

        if result == AuthResult.VALID_PASSWORD_MFA_REQUIRED:
            self.console.print(
                f"[yellow][!][/yellow] {label} - [yellow]MFA Required[/yellow]"
            )
            return

        if result == AuthResult.VALID_PASSWORD_CA_BLOCKED:
            self.console.print(
                f"[yellow][!][/yellow] {label} - [yellow]CA Policy Blocked[/yellow]"
            )
            return

        if result == AuthResult.VALID_PASSWORD_EXPIRED:
            self.console.print(
                f"[yellow][!][/yellow] {label} - [yellow]Password Expired[/yellow]"
            )
            return

        if result == AuthResult.ACCOUNT_LOCKED:
            self.console.print(
                f"[bold red][LOCKED][/bold red] {label} - [red]Account Locked[/red]"
            )
            return

        if result == AuthResult.RATE_LIMITED:
            self.console.print(
                f"[bold red][RATE][/bold red] {label} - [red]Rate Limited[/red]"
            )
            return

        # Verbose-only results
        if not self.verbose:
            return

        if result == AuthResult.INVALID_PASSWORD:
            self.console.print(f"[dim][-] {label} - Invalid Password[/dim]")
            return

        if result in (AuthResult.ACCOUNT_DISABLED, AuthResult.USER_NOT_FOUND):
            self.console.print(f"[dim][-] {label} - {result.value}[/dim]")
            return

        # Catch-all for unknown results
        self.console.print(f"[dim][-] {label} - {result.value}[/dim]")

    def summary_table(self, valid_creds: list[ValidCredential]) -> None:
        """Print a Rich table summarizing all valid credentials found."""
        if not valid_creds:
            self.console.print("\n[dim]No valid credentials discovered.[/dim]")
            return

        table = Table(title="Valid Credentials", show_lines=True)
        table.add_column("Username", style="cyan", no_wrap=True)
        table.add_column("Password", style="white")
        table.add_column("Result", style="yellow")
        table.add_column("MFA Type", style="magenta")

        for cred in valid_creds:
            result_style = self._result_style(cred.result)
            table.add_row(
                cred.username,
                cred.password,
                Text(cred.result.value, style=result_style),
                cred.mfa_type or "N/A",
            )

        self.console.print()
        self.console.print(table)

    def lockout_warning(self, count: int) -> None:
        """Print a bold red lockout threshold warning."""
        self.console.print(
            f"\n[bold red]WARNING: {count} account(s) locked out! "
            "Pausing spray to avoid further lockouts.[/bold red]\n"
        )

    def print_enum_result(self, username: str, exists: bool, method: str) -> None:
        """Print a color-coded user enumeration result."""
        if exists:
            self.console.print(
                f"[bold green][+][/bold green] {username} - "
                f"[green]VALID[/green] [dim]({method})[/dim]"
            )
        elif self.verbose:
            self.console.print(
                f"[dim][-] {username} - NOT FOUND ({method})[/dim]"
            )

    def error(self, message: str) -> None:
        """Print a red error message."""
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def info(self, message: str) -> None:
        """Print an info message."""
        self.console.print(f"[bold blue]>[/bold blue] {message}")

    def debug(self, message: str) -> None:
        """Print a debug message (only in verbose mode)."""
        if not self.verbose:
            return
        self.console.print(f"[dim]  {message}[/dim]")

    @staticmethod
    def _result_style(result: AuthResult) -> str:
        """Map an AuthResult to a Rich style string."""
        style_map = {
            AuthResult.SUCCESS: "bold green",
            AuthResult.VALID_PASSWORD_MFA_ENROLLMENT: "bold red",
            AuthResult.VALID_PASSWORD_MFA_REQUIRED: "yellow",
            AuthResult.VALID_PASSWORD_CA_BLOCKED: "yellow",
            AuthResult.VALID_PASSWORD_EXPIRED: "yellow",
            AuthResult.ACCOUNT_LOCKED: "red",
            AuthResult.RATE_LIMITED: "red",
        }
        return style_map.get(result, "dim")
