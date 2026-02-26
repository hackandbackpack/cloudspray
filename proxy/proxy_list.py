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
        """Test connectivity through all proxies against the actual target.

        Returns False if any proxy fails, since a dead proxy in the rotation
        would cause intermittent failures during operation.
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
