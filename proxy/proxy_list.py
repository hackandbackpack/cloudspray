import logging
import re

import requests

from cloudspray.proxy.base import ProxyProvider
from cloudspray.utils import read_lines

logger = logging.getLogger(__name__)

# Matches protocol://host:port patterns for HTTP and SOCKS5 proxies
_PROXY_URL_PATTERN = re.compile(r"^(https?|socks5)://[a-zA-Z0-9._-]+:\d+$")


class ProxyListProvider(ProxyProvider):
    """Static proxy list -- reads proxies from a file and round-robins through them.

    Supports both SOCKS5 and HTTP proxies.
    Format per line: protocol://host:port
        (e.g., socks5://1.2.3.4:1080, http://proxy.example.com:8080)
    """

    def __init__(self, proxy_file: str):
        """
        Args:
            proxy_file: Path to file with one proxy URL per line.
        """
        self._proxy_file = proxy_file
        self._proxies: list[str] = []
        self._round_robin_index = 0

    @property
    def name(self) -> str:
        return "proxy-list"

    def setup(self, target_url: str) -> None:
        """Read the proxy file, parse each line, and validate the URL format.

        Blank lines and comment lines (starting with #) are skipped
        by the underlying read_lines utility.
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
        """Round-robin through the loaded proxy list."""
        if not self._proxies:
            raise RuntimeError("No proxies loaded. Call setup() first.")

        proxy = self._proxies[self._round_robin_index % len(self._proxies)]
        self._round_robin_index += 1
        return proxy

    def teardown(self) -> None:
        """No-op -- nothing to clean up for a static proxy list."""

    def health_check(self) -> bool:
        """Test connectivity through the first proxy in the list."""
        if not self._proxies:
            return False

        test_proxy = self._proxies[0]
        proxy_dict = {"http": test_proxy, "https": test_proxy}

        try:
            resp = requests.get(
                "https://httpbin.org/ip",
                proxies=proxy_dict,
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException:
            logger.warning("Health check failed for proxy: %s", test_proxy)
            return False
