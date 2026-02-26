from abc import ABC, abstractmethod


class ProxyProvider(ABC):
    """Abstract base class for proxy rotation providers."""

    @abstractmethod
    def setup(self, target_url: str) -> None:
        """Initialize the proxy infrastructure for the given target URL.

        Args:
            target_url: The URL that will be proxied
                (e.g., https://login.microsoftonline.com).
        """

    @abstractmethod
    def get_proxy_url(self) -> str:
        """Return the next proxy URL to use.

        Returns:
            Proxy URL string
            (e.g., https://abc123.execute-api.us-east-1.amazonaws.com/proxy).
        """

    @abstractmethod
    def teardown(self) -> None:
        """Clean up proxy infrastructure (delete API gateways, containers, etc.)."""

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the proxy is operational.

        Returns:
            True if healthy, False otherwise.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name for logging."""
