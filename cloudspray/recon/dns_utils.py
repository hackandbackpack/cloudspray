"""Shared DNS utility functions for recon modules."""

import dns.resolver
import dns.exception

# Maps substrings found in MX hostnames to their mail provider names.
# Checked in order; more specific patterns should come before general ones
# (e.g. "pphosted.com" before "proofpoint") to produce the best label.
MX_PROVIDERS = {
    "pphosted.com": "Proofpoint",
    "proofpoint": "Proofpoint",
    "protection.outlook.com": "Microsoft 365",
    "mail.protection": "Microsoft 365",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "mimecast": "Mimecast",
    "barracuda": "Barracuda",
}


def identify_mail_provider(domain: str) -> tuple[str, str]:
    """Check MX records and identify the mail provider.

    Returns:
        Tuple of (provider_name, mx_host). Both empty strings if no MX found.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return "", ""

    mx_records = sorted(answers, key=lambda r: r.preference)
    if not mx_records:
        return "", ""

    mx_host = str(mx_records[0].exchange).rstrip(".")
    mx_lower = mx_host.lower()

    for pattern, provider in MX_PROVIDERS.items():
        if pattern in mx_lower:
            return provider, mx_host

    return "Unknown", mx_host
