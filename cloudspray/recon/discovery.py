"""IdP discovery: tenant validation, federation detection, DNS-based IdP identification."""

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
    """Performs automated IdP discovery for a target domain.

    Queries Azure AD OpenID configuration, user realm info, DNS TXT records,
    MX records, and autodiscover CNAME to build a complete picture of a
    domain's identity and mail infrastructure.
    """

    def __init__(self, domain: str):
        self._domain = domain

    def run(self, reporter) -> ReconResult:
        """Execute full recon: tenant check, user realm, DNS federation, MX, autodiscover."""
        result = ReconResult(domain=self._domain)

        reporter.info(f"Checking Azure AD tenant for {self._domain}...")
        result.tenant_id, _ = self._check_azure_tenant()

        if result.tenant_id:
            reporter.info("Querying user realm info...")
            result.namespace_type, result.federation_brand = self._get_user_realm()

        reporter.info("Checking DNS TXT records for federation...")
        result.idp_name, result.idp_host, result.federation_url = (
            self._parse_federation_from_txt()
        )

        reporter.info("Checking MX records...")
        result.mail_provider, result.mail_host = self._check_mx()

        reporter.info("Checking autodiscover CNAME...")
        result.autodiscover_cname = self._check_autodiscover()
        result.has_m365 = (
            result.autodiscover_cname is not None
            and "outlook" in result.autodiscover_cname.lower()
        )

        return result

    def _check_azure_tenant(self) -> tuple[str | None, str | None]:
        """Check if the domain has an Azure AD tenant via OpenID configuration."""
        url = f"https://login.microsoftonline.com/{self._domain}/.well-known/openid-configuration"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return None, None
            data = resp.json()
            issuer = data.get("issuer", "")
            tenant_id = issuer.rstrip("/").split("/")[-1] if issuer else None
            return tenant_id, None
        except (requests.RequestException, ValueError):
            return None, None

    def _get_user_realm(self) -> tuple[str | None, str | None]:
        """Query Microsoft user realm endpoint for namespace type and federation brand."""
        url = (
            f"https://login.microsoftonline.com/getuserrealm.srf"
            f"?login=user@{self._domain}&json=1"
        )
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                return None, None
            data = resp.json()
            return data.get("NameSpaceType"), data.get("FederationBrandName")
        except (requests.RequestException, ValueError):
            return None, None

    def _parse_federation_from_txt(self) -> tuple[str | None, str | None, str | None]:
        """Scan DNS TXT records for DirectFedAuthUrl pointing to an IdP."""
        try:
            answers = dns.resolver.resolve(self._domain, "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            Exception,
        ):
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
        """Identify the IdP vendor from a federation URL based on hostname and path."""
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
        """Look up MX records and identify the mail provider."""
        try:
            answers = dns.resolver.resolve(self._domain, "MX")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            Exception,
        ):
            return None, None

        mx_records = sorted(answers, key=lambda r: r.preference)
        if not mx_records:
            return None, None

        mx_host = str(mx_records[0].exchange).rstrip(".")
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
        """Check for autodiscover CNAME pointing to Outlook/M365."""
        try:
            answers = dns.resolver.resolve(f"autodiscover.{self._domain}", "CNAME")
            for record in answers:
                return str(record.target).rstrip(".")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            Exception,
        ):
            pass
        return None
