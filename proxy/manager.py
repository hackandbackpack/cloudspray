import logging
import time

import requests

from cloudspray.proxy.base import ProxyProvider

logger = logging.getLogger(__name__)


class ProxyManager:
    """Manages multiple proxy providers with round-robin selection and failover.

    Wraps all outbound requests. Provides configured requests.Session objects
    with proxy settings applied.
    """

    def __init__(self):
        self._providers: list[ProxyProvider] = []
        self._current_index: int = 0
        self._unhealthy: dict[
            str, float
        ] = {}  # provider_name -> unhealthy_since timestamp
        self._cooldown_seconds: float = 300.0  # 5 minutes

    def add_provider(self, provider: ProxyProvider) -> None:
        """Register a proxy provider."""
        self._providers.append(provider)
        logger.info("Registered proxy provider: %s", provider.name)

    def setup_all(self, target_url: str) -> None:
        """Call setup() on all registered providers."""
        for provider in self._providers:
            logger.info("Setting up proxy provider: %s", provider.name)
            provider.setup(target_url)

    def get_session(self) -> requests.Session:
        """Get a requests.Session configured with the next available proxy.

        Round-robins through all healthy providers. Skips unhealthy providers
        unless they have been in cooldown for longer than 5 minutes (then retries).

        Returns a Session with proxies dict set for both http and https.

        Raises:
            RuntimeError: If no healthy providers are available.
        """
        if not self._providers:
            raise RuntimeError("No proxy providers registered.")

        # Try each provider once, starting from current index
        attempts = len(self._providers)
        for _ in range(attempts):
            provider = self._providers[self._current_index % len(self._providers)]
            self._current_index += 1

            if not self._is_healthy(provider):
                continue

            proxy_url = provider.get_proxy_url()
            session = requests.Session()
            session.proxies = {"http": proxy_url, "https": proxy_url}
            return session

        raise RuntimeError(
            "All proxy providers are unhealthy. "
            f"Cooldown period is {self._cooldown_seconds} seconds."
        )

    def teardown_all(self) -> None:
        """Call teardown() on all registered providers."""
        for provider in self._providers:
            logger.info("Tearing down proxy provider: %s", provider.name)
            try:
                provider.teardown()
            except Exception:
                logger.exception("Error during teardown of provider: %s", provider.name)

    def mark_unhealthy(self, provider_name: str) -> None:
        """Mark a provider as unhealthy, starting the 5-min cooldown."""
        self._unhealthy[provider_name] = time.monotonic()
        logger.warning("Marked provider as unhealthy: %s", provider_name)

    def _is_healthy(self, provider: ProxyProvider) -> bool:
        """Check if provider is healthy (not in cooldown or cooldown expired)."""
        unhealthy_since = self._unhealthy.get(provider.name)
        if unhealthy_since is None:
            return True

        elapsed = time.monotonic() - unhealthy_since
        if elapsed >= self._cooldown_seconds:
            # Cooldown expired -- give it another chance
            del self._unhealthy[provider.name]
            logger.info("Cooldown expired for %s, marking as healthy", provider.name)
            return True

        return False
