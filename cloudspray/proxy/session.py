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

    def __init__(
        self,
        provider: ProxyProvider,
        target_host: str,
        forwarded_for: str | None = None,
    ) -> None:
        """Initialize the session with a proxy provider and target host.

        Args:
            provider: A ProxyProvider instance that supplies gateway URLs
                via get_proxy_url(). Typically an AWSGatewayProvider.
            target_host: The hostname to intercept in outgoing requests
                (e.g., "login.microsoftonline.com"). Any request URL
                containing this hostname will be rewritten to go through
                the proxy.
            forwarded_for: Value to send in ``X-My-X-Forwarded-For`` on
                proxied requests. Defaults to the provider's configured value
                when it exposes one, otherwise empty. See the note below on
                why this header matters.
        """
        super().__init__()
        self.provider = provider
        self.target_host = target_host
        if forwarded_for is None:
            forwarded_for = getattr(provider, "forwarded_for", "")
        self.forwarded_for = forwarded_for
        self.last_proxy_url: str = ""

    def _rewrite_url(self, url: str) -> tuple[str, bool]:
        """Rewrite a URL to route through the proxy gateway if it targets our host.

        Checks both https:// and http:// schemes so that plain-HTTP URLs
        are also routed through the gateway instead of leaking directly
        to the target.

        Args:
            url: The original request URL.

        Returns:
            ``(url, rewritten)`` where ``rewritten`` reports whether the URL
            matched the target host and was sent through the gateway.
        """
        for scheme in ("https://", "http://"):
            prefix = f"{scheme}{self.target_host}"
            if url.startswith(prefix):
                gateway_url = self.provider.get_proxy_url().rstrip("/")
                self.last_proxy_url = gateway_url
                return url.replace(prefix, gateway_url, 1), True
        return url, False

    def request(self, method, url, **kwargs):
        """Override the base request method to rewrite URLs before sending.

        If the request URL targets the configured host (over either HTTP or
        HTTPS), the scheme + host prefix is replaced with the next gateway
        URL from the provider. URLs that don't match pass through unchanged.

        Proxied requests also carry ``X-My-X-Forwarded-For``. The gateway is
        configured to map that header onto X-Forwarded-For, replacing the value
        API Gateway would otherwise populate with our real source IP. Without
        sending it, the mapping has nothing to substitute and the operator's
        address can reach the target in a header.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: The original request URL.
            **kwargs: All other arguments passed through to requests.Session.

        Returns:
            requests.Response from the (possibly rewritten) request.
        """
        url, rewritten = self._rewrite_url(url)
        if rewritten:
            # Copy rather than mutate: callers (and MSAL) reuse header dicts.
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("X-My-X-Forwarded-For", self.forwarded_for)
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)
