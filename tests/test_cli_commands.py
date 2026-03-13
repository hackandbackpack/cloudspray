"""Smoke tests verifying all CLI commands are registered."""

from click.testing import CliRunner

from cloudspray.cli import cli


def test_recon_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["recon", "--help"])
    assert result.exit_code == 0
    assert "discover" in result.output.lower() or "identity" in result.output.lower()


def test_okta_spray_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["okta-spray", "--help"])
    assert result.exit_code == 0
    assert "okta" in result.output.lower()


def test_footprint_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["footprint", "--help"])
    assert result.exit_code == 0
    assert "dns" in result.output.lower() or "saas" in result.output.lower()


def test_spray_has_force_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["spray", "--help"])
    assert result.exit_code == 0
    assert "--force" in result.output


def test_enum_has_force_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["enum", "--help"])
    assert result.exit_code == 0
    assert "--force" in result.output


def test_all_commands_registered():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ["enum", "spray", "recon", "okta-spray", "footprint", "format", "post", "report"]:
        assert cmd in result.output, f"Command '{cmd}' not found in CLI help"
