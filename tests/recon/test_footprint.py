"""Tests for SaaS footprinting module."""

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from cloudspray.recon.footprint import SaaSFootprinter


class TestParseTxtServices:
    """Verify TXT record matching identifies SaaS services."""

    def test_atlassian_record(self):
        records = ["atlassian-domain-verification=abc123"]
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services(records)
        assert "Atlassian" in services

    def test_multiple_services(self):
        records = [
            "atlassian-domain-verification=abc123",
            "google-site-verification=xyz789",
            "MS=ms12345678",
        ]
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services(records)
        assert "Atlassian" in services
        assert "Google Workspace" in services
        assert "Microsoft 365" in services

    def test_no_services(self):
        records = ["v=spf1 -all", "some-random-txt-record"]
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services(records)
        assert len(services) == 0


class TestParseSpf:
    """Verify SPF record parsing extracts include domains."""

    def test_spf_with_includes(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf(
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
        )
        assert "spf.protection.outlook.com" in includes
        assert "_spf.google.com" in includes

    def test_spf_no_includes(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf("v=spf1 -all")
        assert len(includes) == 0

    def test_non_spf_record(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf("google-site-verification=abc123")
        assert len(includes) == 0
