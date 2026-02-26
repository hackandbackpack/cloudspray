import logging
import time
from types import TracebackType

import requests

from cloudspray.proxy.base import ProxyProvider

logger = logging.getLogger(__name__)


class ProxyManager:
    """Manages multiple proxy providers with round-robin selection and failover.

    Wraps all outbound requests. Provides configured requests.Session objects
    with proxy settings applied. Supports context manager usage for reliable
    teardown:

        with ProxyManager() as mgr:
            mgr.add_provider(...)
            mgr.setup_all(target)
            session = mgr.get_session()
    """

    def __init__(self):
        self._providers: list[ProxyProvider] = []
        self._current_index: int = 0
        # Keyed by provider index to avoid name collisions
        self._unhealthy: dict[int, float] = {}
        self._cooldown_seconds: float = 300.0  # 5 minutes

    def __enter__(self) -> "ProxyManager":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.teardown_all()

    def add_provider(self, provider: ProxyProvider) -> None:
        """Register a proxy provider."""
        self._providers.append(provider)
        logger.info("Registered proxy provider: %s", provider.name)

    def setup_all(self, target_url: str) -> None:
        """Call setup() on all registered providers.

        If any provider's setup fails, already-setup providers are torn down
        before re-raising the exception to prevent orphaned cloud resources.
        """
        setup_done: list[ProxyProvider] = []
        for provider in self._providers:
            logger.info("Setting up proxy provider: %s", provider.name)
            try:
                provider.setup(target_url)
                setup_done.append(provider)
            except Exception:
                logger.exception(
                    "Setup failed for %s, tearing down %d already-setup providers",
                    provider.name,
                    len(setup_done),
                )
                for done_provider in setup_done:
                    try:
                        done_provider.teardown()
                    except Exception:
                        logger.exception(
                            "Error during rollback teardown of %s", done_provider.name
                        )
                raise

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
            idx = self._current_index % len(self._providers)
            provider = self._providers[idx]
            self._current_index += 1

            if not self._is_healthy(idx, provider):
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

    def mark_unhealthy(self, provider_index: int) -> None:
        """Mark a provider as unhealthy by its index, starting the 5-min cooldown."""
        self._unhealthy[provider_index] = time.monotonic()
        provider_name = self._providers[provider_index].name
        logger.warning("Marked provider %d (%s) as unhealthy", provider_index, provider_name)

    def _is_healthy(self, provider_index: int, provider: ProxyProvider) -> bool:
        """Check if provider is healthy (not in cooldown or cooldown expired)."""
        unhealthy_since = self._unhealthy.get(provider_index)
        if unhealthy_since is None:
            return True

        elapsed = time.monotonic() - unhealthy_since
        if elapsed >= self._cooldown_seconds:
            del self._unhealthy[provider_index]
            logger.info("Cooldown expired for %s, marking as healthy", provider.name)
            return True

        return False
