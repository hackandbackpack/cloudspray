"""Requests session that routes traffic through Fireprox (API Gateway) proxies.

This module implements the core of the Fireprox technique: URL rewriting.

Why URL rewriting instead of HTTP proxy headers?
    A traditional forward proxy works by setting HTTP proxy headers -- the
    client says "connect me to example.com" and the proxy forwards the
    request. But AWS API Gateway is a *reverse* proxy, not a forward proxy.
    It doesn't read proxy headers; instead, it receives requests at its own
    URL and forwards them to a pre-configured backend.

    So instead of:
        POST https://login.microsoftonline.com/oauth2/token
        (with proxy headers pointing at AWS)

    We send:
        POST https://abc123.execute-api.us-east-1.amazonaws.com/proxy/oauth2/token
        (no proxy headers needed -- the gateway forwards to Microsoft)

    The gateway strips its own URL prefix and appends the remaining path
    (/oauth2/token) to the configured backend URL (login.microsoftonline.com),
    then makes the request from an AWS IP address.

This approach is transparent to the rest of the codebase. Code that builds
URLs targeting login.microsoftonline.com works unchanged -- this session
intercepts the request and swaps the host portion before it hits the network.
"""

import requests

from cloudspray.proxy.base import ProxyProvider


class FireproxSession(requests.Session):
    """A requests.Session that transparently rewrites URLs to route through
    API Gateway reverse proxies, giving each request a different source IP.

    Instead of setting HTTP proxy headers (which API Gateway ignores), this
    session replaces the target hostname in each request URL with the
    gateway's invoke URL. The gateway then forwards the request to the
    real target from a rotating pool of AWS IP addresses.

    Example:
        Original URL:  https://login.microsoftonline.com/common/oauth2/token
        Rewritten URL: https://abc123.execute-api.us-east-1.amazonaws.com/proxy/common/oauth2/token

    Usage::

        provider = AWSGatewayProvider(key, secret, ["us-east-1"])
        provider.setup("https://login.microsoftonline.com")
        session = FireproxSession(provider, "login.microsoftonline.com")
        # This request goes through the API Gateway, not directly to Microsoft
        session.post("https://login.microsoftonline.com/common/oauth2/token", data=payload)

    Attributes:
        provider: The proxy provider that supplies gateway URLs.
        target_host: The hostname to intercept and rewrite (e.g.,
            "login.microsoftonline.com").
        last_proxy_url: The gateway URL used for the most recent request,
            useful for debugging and logging.
    """

    def __init__(self, provider: ProxyProvider, target_host: str) -> None:
        """Initialize the session with a proxy provider and target host.

        Args:
            provider: A ProxyProvider instance that supplies gateway URLs
                via get_proxy_url(). Typically an AWSGatewayProvider.
            target_host: The hostname to intercept in outgoing requests
                (e.g., "login.microsoftonline.com"). Any request URL
                containing this hostname will be rewritten to go through
                the proxy.
        """
        super().__init__()
        self.provider = provider
        self.target_host = target_host
        self.last_proxy_url: str = ""

    def request(self, method, url, **kwargs):
        """Override the base request method to rewrite URLs before sending.

        If the request URL contains the target host, the https://<target_host>
        prefix is replaced with the next gateway URL from the provider. URLs
        that don't match the target host pass through unchanged (e.g.,
        requests to other APIs).

        Args:
            method: HTTP method (GET, POST, etc.).
            url: The original request URL.
            **kwargs: All other arguments passed through to requests.Session.

        Returns:
            requests.Response from the (possibly rewritten) request.
        """
        # Build the prefix to match against the URL
        target_prefix = f"https://{self.target_host}"
        if self.target_host in url:
            # Get the next gateway URL and swap it in place of the target host.
            # The path portion (everything after the host) is preserved, so
            # /common/oauth2/token stays intact after the rewrite.
            gateway_url = self.provider.get_proxy_url()
            self.last_proxy_url = gateway_url
            url = url.replace(target_prefix, gateway_url, 1)
        return super().request(method, url, **kwargs)
