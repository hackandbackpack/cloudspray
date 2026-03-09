"""Proxy manager that orchestrates multiple proxy providers with failover.

The ProxyManager is the main entry point for the rest of CloudSpray to get
proxy-configured HTTP sessions. It wraps one or more ProxyProvider instances
(AWS Gateway, Azure ACI, static list) and handles:

    - Round-robin selection across providers for load distribution
    - Health tracking with cooldown periods so a temporarily failed provider
      doesn't block the entire spray operation
    - Guaranteed teardown of cloud resources via context manager (__enter__/
      __exit__), preventing orphaned API Gateways or Azure containers that
      would incur ongoing charges
    - Rollback during setup -- if one provider fails to set up, already-
      provisioned providers are torn down to avoid partial deployments

Typical usage::

    with ProxyManager() as mgr:
        mgr.add_provider(AWSGatewayProvider(key, secret, ["us-east-1"]))
        mgr.add_provider(ProxyListProvider("proxies.txt"))
        mgr.setup_all("https://login.microsoftonline.com")

        # Each call returns a session routed through the next healthy provider
        session = mgr.get_session()
        response = session.post(login_url, data=payload)

Note: For AWS Gateway providers, you typically use FireproxSession instead of
ProxyManager.get_session(), since the gateway requires URL rewriting rather
than HTTP proxy headers. ProxyManager.get_session() sets standard proxy
headers, which works correctly for Azure ACI and static proxy list providers.
"""

import logging
import time
from types import TracebackType

import requests

from cloudspray.proxy.base import ProxyProvider

logger = logging.getLogger(__name__)


class ProxyManager:
    """Orchestrates multiple proxy providers with round-robin and failover.

    Maintains a list of ProxyProvider instances and distributes requests
    across them. Providers that fail health checks are placed in a 5-minute
    cooldown before being retried. Context manager support guarantees that
    all cloud resources are torn down even if an exception occurs.

    Attributes:
        _providers: Registered proxy provider instances.
        _current_index: Round-robin counter for provider selection.
        _unhealthy: Maps provider index to the monotonic timestamp when
            it was marked unhealthy. Used for cooldown tracking.
        _cooldown_seconds: How long an unhealthy provider is skipped before
            being retried (default: 300 seconds / 5 minutes).
    """

    def __init__(self):
        """Initialize an empty proxy manager with no providers registered."""
        self._providers: list[ProxyProvider] = []
        self._current_index: int = 0
        # Keyed by provider index (not name) to avoid collisions when
        # multiple instances of the same provider type are registered
        self._unhealthy: dict[int, float] = {}
        self._cooldown_seconds: float = 300.0  # 5 minutes

    def __enter__(self) -> "ProxyManager":
        """Enter the context manager. Returns self for use in 'with' blocks."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context manager, tearing down all providers.

        This guarantees cloud resources (API Gateways, Azure containers) are
        cleaned up even if the spray operation raises an exception.
        """
        self.teardown_all()

    def add_provider(self, provider: ProxyProvider) -> None:
        """Register a proxy provider for use in the rotation.

        Args:
            provider: A ProxyProvider instance to add to the pool.
        """
        self._providers.append(provider)
        logger.info("Registered proxy provider: %s", provider.name)

    def setup_all(self, target_url: str) -> None:
        """Initialize all registered providers for the given target URL.

        Calls setup() on each provider in order. If any provider's setup
        fails, all previously successful providers are torn down before
        re-raising the exception. This prevents orphaned cloud resources
        (e.g., API Gateways left running without a matching teardown).

        Args:
            target_url: The URL to proxy (e.g.,
                "https://login.microsoftonline.com").

        Raises:
            Exception: Re-raises whatever exception caused the setup failure,
                after rolling back already-provisioned providers.
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
