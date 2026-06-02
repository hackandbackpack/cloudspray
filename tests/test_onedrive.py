"""Tests for OneDrive tenant slug derivation."""
from cloudspray.enumerators.onedrive import OneDriveEnumerator


def test_simple_domain():
    assert OneDriveEnumerator._derive_tenant_slug("example.com") == "example"


def test_subdomain():
    assert OneDriveEnumerator._derive_tenant_slug("corp.example.com") == "example"


def test_deep_subdomain():
    assert OneDriveEnumerator._derive_tenant_slug("a.b.example.com") == "example"


def test_bare_name():
    assert OneDriveEnumerator._derive_tenant_slug("example") == "example"
