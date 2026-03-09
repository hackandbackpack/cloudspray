"""Azure Container Instances proxy provider for IP rotation via forward proxies.

An alternative to the Fireprox/API Gateway approach. Instead of using reverse
proxy URL rewriting, this provider deploys lightweight tinyproxy containers in
Azure, each with its own public IP address. The caller uses standard HTTP
proxy headers to route traffic through these containers.

Why Azure IPs are useful for M365 spraying:
    Microsoft owns Azure's IP ranges. Traffic originating from Azure IPs can
    blend in with legitimate Microsoft 365 traffic, which also originates from
    Azure data centers. This can reduce the likelihood of IP-based blocking
    compared to using random VPN or residential proxy IPs.

Architecture:
    - A temporary Azure Resource Group is created to hold all containers
    - Multiple tinyproxy containers are deployed across configured regions
    - Each container gets a unique public IP on port 8888
    - Requests are distributed across containers via round-robin
    - On teardown, all containers and the resource group are deleted

Unlike the Fireprox approach (which rewrites URLs), this provider works as a
traditional forward proxy -- the caller sets HTTP proxy headers and the
tinyproxy container forwards the request to the target.

Dependencies:
    azure-identity, azure-mgmt-containerinstance, and azure-mgmt-resource are
    required but lazily imported so the rest of the codebase doesn't depend on
    them when using other proxy backends.
"""

import logging
import socket

from cloudspray.proxy.base import ProxyProvider
from cloudspray.utils import random_suffix

logger = logging.getLogger(__name__)

# Container configuration constants
PROXY_PORT = 8888  # Port tinyproxy listens on inside the container
CONTAINER_CPU = 0.5  # Half a vCPU is plenty for a lightweight proxy
CONTAINER_MEMORY_GB = 0.5  # 512 MB RAM -- tinyproxy has minimal memory needs
CONTAINER_IMAGE = "tinyproxy/tinyproxy:latest"  # Lightweight HTTP/HTTPS proxy


def _require_azure_deps():
    """Lazy-import Azure SDK packages, raising clear errors if missing.

    Each Azure SDK package is imported separately with its own error message
    so the user knows exactly which package to install.

    Returns:
        dict: A mapping of class names to their imported classes, including
        credential, client, and container model classes.

    Raises:
        ImportError: If any required Azure package is not installed.
    """
    try:
        from azure.identity import ClientSecretCredential
    except ImportError:
        raise ImportError(
            "azure-identity is required for Azure ACI proxy support. "
            "Install it with: pip install azure-identity"
        ) from None

    try:
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient
        from azure.mgmt.containerinstance.models import (
            Container,
            ContainerGroup,
            ContainerPort,
            IpAddress,
            OperatingSystemTypes,
            Port,
            ResourceRequests,
            ResourceRequirements,
        )
    except ImportError:
        raise ImportError(
            "azure-mgmt-containerinstance is required for Azure ACI proxy support. "
            "Install it with: pip install azure-mgmt-containerinstance"
        ) from None

    try:
        from azure.mgmt.resource import ResourceManagementClient
    except ImportError:
        raise ImportError(
            "azure-mgmt-resource is required for Azure ACI proxy support. "
            "Install it with: pip install azure-mgmt-resource"
        ) from None

    return {
        "ClientSecretCredential": ClientSecretCredential,
        "ContainerInstanceManagementClient": ContainerInstanceManagementClient,
        "ResourceManagementClient": ResourceManagementClient,
        "Container": Container,
        "ContainerGroup": ContainerGroup,
        "ContainerPort": ContainerPort,
        "IpAddress": IpAddress,
        "OperatingSystemTypes": OperatingSystemTypes,
        "Port": Port,
        "ResourceRequests": ResourceRequests,
        "ResourceRequirements": ResourceRequirements,
    }


class AzureACIProvider(ProxyProvider):
    """Azure Container Instances proxy provider using tinyproxy containers.

    Deploys lightweight forward-proxy containers (tinyproxy) in Azure, each
    with its own unique public IP address. Traffic from Azure IPs blends in
    with legitimate Microsoft 365 traffic since both originate from Microsoft-
    owned IP ranges.

    Unlike AWSGatewayProvider (which uses URL rewriting), this provider works
    as a standard forward proxy -- the caller sets HTTP proxy headers and
    tinyproxy handles the forwarding.

    Lifecycle:
        1. __init__() stores Azure service principal credentials and config
        2. setup() creates a resource group + tinyproxy containers across regions
        3. get_proxy_url() returns container proxy URLs in round-robin order
        4. teardown() deletes all containers and the resource group

    Attributes:
        _subscription_id: Azure subscription to deploy containers in.
        _client_id: Service principal application (client) ID.
        _client_secret: Service principal secret.
        _tenant_id: Azure AD tenant ID for authentication.
        _regions: Azure regions to deploy containers in (e.g., ["eastus"]).
        _container_count: Number of containers to deploy per region.
        _resource_group: Name of the temporary resource group (set during setup).
        _container_ips: Public IPs of deployed containers.
        _container_group_names: Tuples of (region, name) for teardown tracking.
        _round_robin_index: Counter for cycling through container IPs.
    """

    def __init__(
        self,
        subscription_id: str,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        regions: list[str],
        container_count: int = 3,
    ):
        """Initialize the provider with Azure service principal credentials.

        Args:
            subscription_id: Azure subscription ID to deploy containers in.
            client_id: Service principal application (client) ID.
            client_secret: Service principal client secret.
            tenant_id: Azure AD tenant ID for authentication.
            regions: Azure regions to deploy containers in
                (e.g., ["eastus", "westus2", "westeurope"]).
            container_count: Number of tinyproxy containers to create per
                region. Default is 3. Total containers = regions * count.
        """
        self._subscription_id = subscription_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._tenant_id = tenant_id
        self._regions = regions
        self._container_count = container_count
        self._resource_group: str = ""
        self._container_ips: list[str] = []
        self._container_group_names: list[tuple[str, str]] = []  # (region, group_name)
        self._round_robin_index = 0

    @property
    def name(self) -> str:
        return "azure-aci"

    def _get_credential(self, deps: dict):
        """Build an Azure credential from stored service principal details.

        Args:
            deps: The dependency dict returned by _require_azure_deps().

        Returns:
            A ClientSecretCredential instance for authenticating API calls.
        """
        return deps["ClientSecretCredential"](
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

    def setup(self, target_url: str) -> None:
        """Deploy tinyproxy containers across configured regions.

        Creates a temporary resource group in the first configured region,
        then deploys container_count container groups per region. Each
        container group runs tinyproxy and gets its own public IP on port 8888.

        If no containers can be deployed successfully, the empty resource
        group is cleaned up before raising an error.

        Args:
            target_url: The URL being proxied. Not used directly by this
                provider (tinyproxy forwards any target), but required by
                the ProxyProvider interface.

        Raises:
            RuntimeError: If no containers could be deployed in any region.
        """
        deps = _require_azure_deps()
        credential = self._get_credential(deps)
        suffix = random_suffix()
        self._resource_group = f"cloudspray-proxy-{suffix}"

        # Create the resource group in the first region
        resource_client = deps["ResourceManagementClient"](
            credential, self._subscription_id
        )
        primary_location = self._regions[0] if self._regions else "eastus"
        resource_client.resource_groups.create_or_update(
            self._resource_group, {"location": primary_location}
        )
        logger.info(
            "Created resource group %s in %s", self._resource_group, primary_location
        )

        aci_client = deps["ContainerInstanceManagementClient"](
            credential, self._subscription_id
        )

        for region in self._regions:
            for idx in range(self._container_count):
                group_name = f"csproxy-{region}-{idx}-{suffix}"
                try:
                    container = deps["Container"](
                        name=group_name,
                        image=CONTAINER_IMAGE,
                        resources=deps["ResourceRequirements"](
                            requests=deps["ResourceRequests"](
                                cpu=CONTAINER_CPU,
                                memory_in_gb=CONTAINER_MEMORY_GB,
                            )
                        ),
                        ports=[deps["ContainerPort"](port=PROXY_PORT)],
                    )

                    container_group = deps["ContainerGroup"](
                        location=region,
                        containers=[container],
                        os_type=deps["OperatingSystemTypes"].linux,
                        ip_address=deps["IpAddress"](
                            ports=[deps["Port"](protocol="TCP", port=PROXY_PORT)],
                            type="Public",
                        ),
                    )

                    poller = aci_client.container_groups.begin_create_or_update(
                        self._resource_group, group_name, container_group
                    )
                    result = poller.result()

                    public_ip = result.ip_address.ip
                    self._container_ips.append(public_ip)
                    self._container_group_names.append((region, group_name))
                    logger.info(
                        "Deployed container %s in %s (IP: %s)",
                        group_name,
                        region,
                        public_ip,
                    )

                except Exception:
                    logger.exception(
                        "Failed to deploy container %s in %s", group_name, region
                    )

        if not self._container_ips:
            # Clean up the empty resource group before raising
            try:
                self.teardown()
            except Exception:
                logger.exception("Teardown failed during cleanup of empty deployment")
            raise RuntimeError(
                "Failed to deploy any proxy containers. Check Azure credentials."
            )

    def get_proxy_url(self) -> str:
        """Return the next container's proxy URL using round-robin selection.

        Returns a standard HTTP proxy URL (http://ip:port) that can be used
        in requests.Session.proxies or similar proxy configuration.

        Returns:
            Proxy URL like "http://20.42.73.101:8888".

        Raises:
            RuntimeError: If setup() has not been called or no containers exist.
        """
        if not self._container_ips:
            raise RuntimeError("No container IPs available. Call setup() first.")

        ip_addr = self._container_ips[
            self._round_robin_index % len(self._container_ips)
        ]
        self._round_robin_index += 1
        return f"http://{ip_addr}:{PROXY_PORT}"

    def teardown(self) -> None:
        """Delete all container groups and the resource group.

        Container groups are deleted individually first, then the resource
        group itself is deleted. Failures on individual deletions are logged
        but do not prevent cleanup of remaining resources. All internal
        state is reset afterward.
        """
        deps = _require_azure_deps()
        credential = self._get_credential(deps)

        if not self._resource_group:
            return

        # Delete individual container groups first
        aci_client = deps["ContainerInstanceManagementClient"](
            credential, self._subscription_id
        )
        for _region, group_name in self._container_group_names:
            try:
                aci_client.container_groups.begin_delete(
                    self._resource_group, group_name
                ).result()
                logger.info("Deleted container group %s", group_name)
            except Exception:
                logger.exception("Failed to delete container group %s", group_name)

        # Delete the resource group
        resource_client = deps["ResourceManagementClient"](
            credential, self._subscription_id
        )
        try:
            resource_client.resource_groups.begin_delete(self._resource_group).result()
            logger.info("Deleted resource group %s", self._resource_group)
        except Exception:
            logger.exception("Failed to delete resource group %s", self._resource_group)

        self._container_ips.clear()
        self._container_group_names.clear()
        self._resource_group = ""
        self._round_robin_index = 0

    def health_check(self) -> bool:
        """Verify all containers are reachable via TCP connection to port 8888.

        Unlike the AWS provider (which does HTTP health checks), this provider
        uses raw TCP connections because tinyproxy may not respond meaningfully
        to a bare GET request. A successful TCP handshake confirms the
        container is running and the port is open.

        Returns:
            True if all containers accept TCP connections, False if any
            container is unreachable or the connection times out.
        """
        if not self._container_ips:
            return False

        for ip_addr in self._container_ips:
            try:
                sock = socket.create_connection((ip_addr, PROXY_PORT), timeout=5)
                sock.close()
            except OSError:
                logger.warning("Container unreachable: %s:%d", ip_addr, PROXY_PORT)
                return False

        return True
