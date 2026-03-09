"""Abstract base class defining the interface for all proxy providers.

Every proxy backend (AWS API Gateway, Azure ACI, static proxy list) must
implement the ProxyProvider interface. This ensures the ProxyManager can
work with any backend interchangeably -- it calls setup(), get_proxy_url(),
health_check(), and teardown() without knowing the implementation details.

The lifecycle of a provider is:
    1. __init__() -- store credentials and configuration
    2. setup(target_url) -- create cloud resources or load proxy lists
    3. get_proxy_url() -- called repeatedly during operation, returns the
       next proxy endpoint to route traffic through
    4. health_check() -- verify the proxy infrastructure is still working
    5. teardown() -- destroy all cloud resources to avoid ongoing charges
"""

from abc import ABC, abstractmethod


class ProxyProvider(ABC):
    """Abstract base class that all proxy rotation providers must implement.

    Defines the contract for proxy lifecycle management: setup infrastructure,
    provide rotating proxy URLs, verify health, and clean up when done.
    Subclasses handle the specifics of their particular proxy technology
    (API Gateway creation, container deployment, file parsing, etc.).
    """

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
