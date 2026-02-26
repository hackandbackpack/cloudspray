import logging
import random
import socket
import string

from cloudspray.proxy.base import ProxyProvider

logger = logging.getLogger(__name__)

PROXY_PORT = 8888
CONTAINER_CPU = 0.5
CONTAINER_MEMORY_GB = 0.5
CONTAINER_IMAGE = "tinyproxy/tinyproxy:latest"


def _require_azure_deps():
    """Lazy-import Azure SDK packages, raising clear errors if missing."""
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


def _random_suffix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class AzureACIProvider(ProxyProvider):
    """Azure Container Instances proxy -- each container has a unique public IP.

    Deploys lightweight forward-proxy containers (tinyproxy), each with a
    unique public IP address. Traffic from Azure IPs blends with legitimate
    M365 traffic.
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
        """Build an Azure credential from stored service principal details."""
        return deps["ClientSecretCredential"](
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )

    def setup(self, target_url: str) -> None:
        """Deploy tinyproxy containers across configured regions.

        Creates a resource group and then deploys container_count container
        groups per region, each with its own public IP on port 8888.
        """
        deps = _require_azure_deps()
        credential = self._get_credential(deps)
        suffix = _random_suffix()
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
            raise RuntimeError(
                "Failed to deploy any proxy containers. Check Azure credentials."
            )

    def get_proxy_url(self) -> str:
        """Round-robin through deployed container IPs."""
        if not self._container_ips:
            raise RuntimeError("No container IPs available. Call setup() first.")

        ip_addr = self._container_ips[
            self._round_robin_index % len(self._container_ips)
        ]
        self._round_robin_index += 1
        return f"http://{ip_addr}:{PROXY_PORT}"

    def teardown(self) -> None:
        """Delete all container groups and the resource group."""
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
        """Attempt a TCP connection to each container's proxy port."""
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
