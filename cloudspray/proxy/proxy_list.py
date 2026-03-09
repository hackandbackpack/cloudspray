"""Static proxy list provider for IP rotation using pre-existing proxies.

The simplest proxy backend -- reads a list of proxy URLs from a file and
round-robins through them. No cloud infrastructure is created or destroyed;
the user is responsible for maintaining their own proxy servers.

This is useful when:
    - You already have a pool of proxies (residential, data center, etc.)
    - You don't have AWS or Azure credentials
    - You want to use SOCKS5 proxies (which the cloud-based providers don't
      support)

Unlike AWSGatewayProvider (which rewrites URLs for reverse proxy routing),
this provider works with standard HTTP forward proxies and SOCKS5 proxies.
The proxy URL is set in the requests.Session.proxies dict, and the requests
library handles the proxy negotiation.

File format (one proxy per line):
    socks5://1.2.3.4:1080
    http://proxy.example.com:8080
    https://secure-proxy.example.com:443

Lines starting with # and blank lines are ignored (handled by read_lines).
"""

import logging
import re

import requests

from cloudspray.proxy.base import ProxyProvider
from cloudspray.utils import read_lines

logger = logging.getLogger(__name__)

# Validates proxy URL format: protocol://host:port
# Accepted protocols: http, https, socks5
_PROXY_URL_PATTERN = re.compile(r"^(https?|socks5)://[a-zA-Z0-9._-]+:\d+$")


class ProxyListProvider(ProxyProvider):
    """Proxy provider that reads from a static file of proxy URLs.

    Loads proxy URLs from a text file (one per line), validates the format,
    and cycles through them using round-robin selection. Supports HTTP,
    HTTPS, and SOCKS5 proxy protocols.

    Unlike the cloud-based providers, this creates no infrastructure and has
    no teardown step. IP diversity depends entirely on the quality and size
    of the proxy list provided.

    Example proxy file::

        # Data center proxies
        socks5://10.0.0.1:1080
        socks5://10.0.0.2:1080
        http://proxy.example.com:8080

    Attributes:
        _proxy_file: Path to the proxy list file.
        _proxies: Validated proxy URLs loaded from the file.
        _round_robin_index: Counter for cycling through proxies.
    """

    def __init__(self, proxy_file: str):
        """Initialize the provider with a path to a proxy list file.

        Args:
            proxy_file: Absolute or relative path to a text file containing
                one proxy URL per line in protocol://host:port format.
        """
        self._proxy_file = proxy_file
        self._proxies: list[str] = []
        self._round_robin_index = 0

    @property
    def name(self) -> str:
        return "proxy-list"

    def setup(self, target_url: str) -> None:
        """Read the proxy file, validate each URL, and build the proxy list.

        Each line is checked against the expected protocol://host:port format.
        Invalid lines are logged as warnings and skipped. Blank lines and
        comment lines (starting with #) are filtered out by the read_lines
        utility before validation.

        Args:
            target_url: The URL being proxied. Not used by this provider
                (proxies forward any target), but required by the interface.

        Raises:
            ValueError: If no valid proxy URLs are found in the file.
        """
        raw_lines = read_lines(self._proxy_file)
        validated: list[str] = []

        for line in raw_lines:
            if not _PROXY_URL_PATTERN.match(line):
                logger.warning("Skipping invalid proxy URL: %s", line)
                continue
            validated.append(line)

        if not validated:
            raise ValueError(
                f"No valid proxy URLs found in {self._proxy_file}. "
                "Expected format: protocol://host:port "
                "(e.g., socks5://1.2.3.4:1080, http://proxy.example.com:8080)"
            )

        self._proxies = validated
        logger.info("Loaded %d proxies from %s", len(self._proxies), self._proxy_file)

    def get_proxy_url(self) -> str:
        """Return the next proxy URL using round-robin selection.

        Returns:
            A proxy URL like "socks5://1.2.3.4:1080" or
            "http://proxy.example.com:8080".

        Raises:
            RuntimeError: If setup() has not been called or the file was empty.
        """
        if not self._proxies:
            raise RuntimeError("No proxies loaded. Call setup() first.")

        proxy = self._proxies[self._round_robin_index % len(self._proxies)]
        self._round_robin_index += 1
        return proxy

    def teardown(self) -> None:
        """No-op -- nothing to clean up for a static proxy list.

        The proxies are externally managed, so there are no cloud resources
        to destroy or connections to close.
        """

    def health_check(self) -> bool:
        """Test connectivity through every proxy by making a request to Microsoft.

        Each proxy is tested by sending a GET request to
        login.microsoftonline.com through it. Any proxy that fails (network
        error or HTTP 5xx) causes the entire check to return False, since a
        dead proxy in the rotation would cause intermittent failures during
        the spray operation.

        Returns:
            True if all proxies successfully reach the target, False if any
            proxy is unreachable or returns a server error.
        """
        if not self._proxies:
            return False

        for proxy_url in self._proxies:
            proxy_dict = {"http": proxy_url, "https": proxy_url}
            try:
                resp = requests.get(
                    "https://login.microsoftonline.com",
                    proxies=proxy_dict,
                    timeout=10,
                )
                if resp.status_code >= 500:
                    logger.warning(
                        "Health check returned HTTP %d for proxy: %s",
                        resp.status_code,
                        proxy_url,
                    )
                    return False
            except requests.RequestException:
                logger.warning("Health check failed for proxy: %s", proxy_url)
                return False

        return True
