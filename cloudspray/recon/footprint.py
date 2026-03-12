"""SaaS footprinting via DNS TXT, SPF, MX, and DMARC record analysis."""

from dataclasses import dataclass, field

import dns.resolver


# Maps TXT record prefixes to their corresponding SaaS service names.
# When a domain's TXT records contain one of these prefixes, it indicates
# the organization uses that service and has verified domain ownership.
SAAS_TXT_PATTERNS: dict[str, str] = {
    "atlassian-domain-verification": "Atlassian",
    "google-site-verification": "Google Workspace",
    "slack-domain-verification": "Slack",
    "1password-site-verification": "1Password",
    "docusign": "DocuSign",
    "MS=": "Microsoft 365",
    "adobe-sign-verification": "Adobe",
    "adobe-idp-site-verification": "Adobe",
    "miro-verification": "Miro",
    "airtable-verification": "Airtable",
    "teamviewer-sso-verification": "TeamViewer",
    "box-domain-verification": "Box",
    "smartsheet-site-validation": "Smartsheet",
    "pardot": "Salesforce/Pardot",
    "cisco-ci-domain-verification": "Cisco",
    "apple-domain-verification": "Apple",
    "mandrill-domain-verification": "Mailchimp/Mandrill",
}

# Maps SPF include domains to SaaS providers. SPF records list which mail
# servers are authorized to send on behalf of the domain, revealing which
# email/marketing platforms the organization uses.
SPF_INCLUDE_MAP: dict[str, str] = {
    "spf.protection.outlook.com": "Microsoft 365",
    "_spf.google.com": "Google Workspace",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "servers.mcsv.net": "Mailchimp",
    "spf.mandrillapp.com": "Mailchimp/Mandrill",
    "mktomail.com": "Marketo",
    "hubspot.com": "HubSpot",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "salesforce.com": "Salesforce",
    "pphosted.com": "Proofpoint",
    "mimecast": "Mimecast",
}


@dataclass
class FootprintResult:
    """Results from SaaS footprinting for a domain."""

    domain: str
    txt_services: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    spf_services: list[str] = field(default_factory=list)
    mx_provider: str | None = None
    mx_host: str | None = None
    dmarc_record: str | None = None
    dmarc_policy: str | None = None


class SaaSFootprinter:
    """Discovers SaaS services used by a domain through DNS record analysis.

    Examines TXT records for domain verification entries, parses SPF includes
    to identify authorized mail senders, checks MX for mail provider, and
    reads DMARC policy configuration.
    """

    def __init__(self, domain: str):
        self._domain = domain

    def run(self, reporter) -> FootprintResult:
        """Execute full SaaS footprinting scan."""
        result = FootprintResult(domain=self._domain)

        reporter.info(f"Fetching TXT records for {self._domain}...")
        txt_records = self._get_txt_records()

        reporter.info("Matching TXT records to SaaS services...")
        result.txt_services = self._match_txt_services(txt_records)

        reporter.info("Parsing SPF record...")
        spf_record = next((r for r in txt_records if r.startswith("v=spf1")), None)
        if spf_record:
            result.spf_includes = self._parse_spf(spf_record)
            result.spf_services = self._identify_spf_services(result.spf_includes)

        reporter.info("Checking MX records...")
        result.mx_provider, result.mx_host = self._check_mx()

        reporter.info("Checking DMARC record...")
        result.dmarc_record, result.dmarc_policy = self._check_dmarc()

        return result

    def _get_txt_records(self) -> list[str]:
        """Fetch all TXT records for the domain."""
        try:
            answers = dns.resolver.resolve(self._domain, "TXT")
            return [record.to_text().strip('"') for record in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            Exception,
        ):
            return []

    def _match_txt_services(self, txt_records: list[str]) -> list[str]:
        """Match TXT records against known SaaS verification patterns."""
        found = []
        for record in txt_records:
            for prefix, service in SAAS_TXT_PATTERNS.items():
                if prefix in record and service not in found:
                    found.append(service)
        return found

    def _parse_spf(self, spf_record: str) -> list[str]:
        """Extract include domains from an SPF record."""
        if not spf_record.startswith("v=spf1"):
            return []
        includes = []
        for part in spf_record.split():
            if part.startswith("include:"):
                includes.append(part.split(":", 1)[1])
        return includes

    def _identify_spf_services(self, includes: list[str]) -> list[str]:
        """Map SPF include domains to known SaaS service names."""
        services = []
        for include in includes:
            for pattern, service in SPF_INCLUDE_MAP.items():
                if pattern in include and service not in services:
                    services.append(service)
        return services

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
        if "protection.outlook.com" in mx_lower:
            return "Microsoft 365", mx_host
        if "google.com" in mx_lower or "googlemail.com" in mx_lower:
            return "Google Workspace", mx_host
        if "mimecast" in mx_lower:
            return "Mimecast", mx_host
        if "barracuda" in mx_lower:
            return "Barracuda", mx_host

        return "Unknown", mx_host

    def _check_dmarc(self) -> tuple[str | None, str | None]:
        """Fetch DMARC record and extract the policy."""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self._domain}", "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            Exception,
        ):
            return None, None

        for record in answers:
            txt = record.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                policy = None
                for part in txt.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part.split("=", 1)[1].strip()
                        break
                return txt, policy

        return None, None
