"""Tests for IdP discovery module."""

from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

from cloudspray.recon.discovery import ReconDiscovery


class TestParseIdpFromUrl:
    """Verify _parse_idp_from_url identifies IdP provider from federation URLs."""

    def test_okta_url(self):
        name, host = ReconDiscovery._parse_idp_from_url("https://corp.okta.com/sso/saml")
        assert name == "Okta"
        assert host == "corp.okta.com"

    def test_adfs_url(self):
        name, host = ReconDiscovery._parse_idp_from_url("https://sts.contoso.com/adfs/ls")
        assert name == "ADFS"
        assert host == "sts.contoso.com"

    def test_pingfederate_domain(self):
        name, host = ReconDiscovery._parse_idp_from_url(
            "https://sso.pingidentity.com/idp/startSSO"
        )
        assert name == "PingFederate"
        assert host == "sso.pingidentity.com"

    def test_pingfederate_path(self):
        name, host = ReconDiscovery._parse_idp_from_url(
            "https://auth.example.com/pingfederate/sso"
        )
        assert name == "PingFederate"
        assert host == "auth.example.com"

    def test_duo_url(self):
        name, host = ReconDiscovery._parse_idp_from_url(
            "https://sso-abc123.duosecurity.com/saml2/sp"
        )
        assert name == "Duo"
        assert host == "sso-abc123.duosecurity.com"

    def test_unknown_url(self):
        name, host = ReconDiscovery._parse_idp_from_url(
            "https://login.custom-idp.example.com/sso"
        )
        assert name == "Unknown"
        assert host == "login.custom-idp.example.com"


class TestParseFederationFromTxt:
    """Verify DNS TXT record parsing extracts federation URLs."""

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_okta_direct_fed(self, mock_resolve):
        record = MagicMock()
        record.to_text.return_value = '"DirectFedAuthUrl=https://corp.okta.com/sso/saml"'
        mock_resolve.return_value = [record]

        disco = ReconDiscovery("example.com")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()

        assert idp_name == "Okta"
        assert idp_host == "corp.okta.com"
        assert fed_url == "https://corp.okta.com/sso/saml"

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_no_federation_found(self, mock_resolve):
        record = MagicMock()
        record.to_text.return_value = '"v=spf1 include:spf.protection.outlook.com -all"'
        mock_resolve.return_value = [record]

        disco = ReconDiscovery("example.com")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()

        assert idp_name is None
        assert idp_host is None
        assert fed_url is None

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_dns_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        disco = ReconDiscovery("nonexistent.example")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()

        assert idp_name is None
        assert idp_host is None
        assert fed_url is None


class TestCheckAzureTenant:
    """Verify Azure AD tenant detection via OpenID configuration."""

    @patch("cloudspray.recon.discovery.requests.get")
    def test_tenant_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "issuer": "https://sts.windows.net/a]b-c-d-e/"
        }
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("contoso.com")
        tenant_id, _ = disco._check_azure_tenant()

        assert tenant_id == "a]b-c-d-e"
        mock_get.assert_called_once_with(
            "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration",
            timeout=10,
        )

    @patch("cloudspray.recon.discovery.requests.get")
    def test_tenant_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("nope.example")
        tenant_id, _ = disco._check_azure_tenant()

        assert tenant_id is None


class TestGetUserRealm:
    """Verify user realm detection via getuserrealm.srf."""

    @patch("cloudspray.recon.discovery.requests.get")
    def test_managed_realm(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "NameSpaceType": "Managed",
            "FederationBrandName": "Contoso",
        }
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("contoso.com")
        ns_type, brand = disco._get_user_realm()

        assert ns_type == "Managed"
        assert brand == "Contoso"

    @patch("cloudspray.recon.discovery.requests.get")
    def test_federated_realm(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "NameSpaceType": "Federated",
            "FederationBrandName": "Example Corp",
        }
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("example.com")
        ns_type, brand = disco._get_user_realm()

        assert ns_type == "Federated"
        assert brand == "Example Corp"
