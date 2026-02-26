import logging

import requests

from cloudspray.proxy.base import ProxyProvider
from cloudspray.utils import random_suffix

logger = logging.getLogger(__name__)


def _require_boto3():
    """Lazy-import boto3, raising a clear error if it is not installed."""
    try:
        import boto3  # noqa: F811

        return boto3
    except ImportError:
        raise ImportError(
            "boto3 is required for AWS API Gateway proxy support. "
            "Install it with: pip install boto3"
        ) from None


class AWSGatewayProvider(ProxyProvider):
    """AWS API Gateway proxy -- each request gets a different source IP.

    Creates REST API gateways with HTTP proxy integration pointing at
    the target URL (e.g., login.microsoftonline.com). AWS assigns a
    different source IP from its pool for each request.

    Multi-region support: creates gateways in multiple AWS regions for
    IP diversity.
    """

    def __init__(self, access_key: str, secret_key: str, regions: list[str]):
        """
        Args:
            access_key: AWS access key ID.
            secret_key: AWS secret access key.
            regions: List of AWS region slugs to create gateways in.
        """
        self._access_key = access_key
        self._secret_key = secret_key
        self._regions = regions
        self._gateway_urls: list[str] = []
        self._api_ids: list[tuple[str, str]] = []  # (region, api_id)
        self._round_robin_index = 0

    @property
    def name(self) -> str:
        return "aws-api-gateway"

    def setup(self, target_url: str) -> None:
        """Create REST API gateways in each configured region.

        Each gateway gets an HTTP_PROXY integration that forwards traffic
        to the target URL, using a greedy path variable for flexibility.
        """
        boto3 = _require_boto3()

        # Strip trailing slash so integration URI is clean
        target_url = target_url.rstrip("/")

        for region in self._regions:
            client = boto3.client(
                "apigateway",
                region_name=region,
                aws_access_key_id=self._access_key,
                aws_secret_access_key=self._secret_key,
            )
            api_name = f"cloudspray-{region}-{random_suffix()}"

            try:
                api_response = client.create_rest_api(
                    name=api_name,
                    description="HTTP proxy integration",
                    endpointConfiguration={"types": ["REGIONAL"]},
                )
                api_id = api_response["id"]

                # Track immediately so teardown can clean up on later failures
                self._api_ids.append((region, api_id))

                # Get root resource ID
                resources = client.get_resources(restApiId=api_id)
                root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")

                # Create greedy path resource: /{proxy+}
                proxy_resource = client.create_resource(
                    restApiId=api_id,
                    parentId=root_id,
                    pathPart="{proxy+}",
                )
                resource_id = proxy_resource["id"]

                # Create ANY method with HTTP_PROXY integration
                client.put_method(
                    restApiId=api_id,
                    resourceId=resource_id,
                    httpMethod="ANY",
                    authorizationType="NONE",
                    requestParameters={"method.request.path.proxy": True},
                )

                integration_uri = f"{target_url}/{{proxy}}"
                client.put_integration(
                    restApiId=api_id,
                    resourceId=resource_id,
                    httpMethod="ANY",
                    type="HTTP_PROXY",
                    integrationHttpMethod="ANY",
                    uri=integration_uri,
                    requestParameters={
                        "integration.request.path.proxy": "method.request.path.proxy"
                    },
                )

                # Deploy to "proxy" stage
                client.create_deployment(restApiId=api_id, stageName="proxy")

                invoke_url = (
                    f"https://{api_id}.execute-api.{region}.amazonaws.com/proxy"
                )
                self._gateway_urls.append(invoke_url)
                logger.info("Created API Gateway %s in %s", api_id, region)

            except Exception:
                logger.exception("Failed to create API Gateway in %s", region)

        if not self._gateway_urls:
            raise RuntimeError(
                "Failed to create any API gateways. Check credentials and regions."
            )

    def get_proxy_url(self) -> str:
        """Round-robin through created gateway invoke URLs."""
        if not self._gateway_urls:
            raise RuntimeError("No gateway URLs available. Call setup() first.")

        url = self._gateway_urls[self._round_robin_index % len(self._gateway_urls)]
        self._round_robin_index += 1
        return url

    def teardown(self) -> None:
        """Delete all created REST APIs across all regions."""
        boto3 = _require_boto3()

        for region, api_id in self._api_ids:
            try:
                client = boto3.client(
                    "apigateway",
                    region_name=region,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                )
                client.delete_rest_api(restApiId=api_id)
                logger.info("Deleted API Gateway %s in %s", api_id, region)
            except Exception:
                logger.exception(
                    "Failed to delete API Gateway %s in %s", api_id, region
                )

        self._gateway_urls.clear()
        self._api_ids.clear()
        self._round_robin_index = 0

    def health_check(self) -> bool:
        """Make a simple GET to each gateway invoke URL and verify a response."""
        if not self._gateway_urls:
            return False

        for url in self._gateway_urls:
            try:
                resp = requests.get(url, timeout=10)
                # 200-499 range means the gateway itself is reachable;
                # 403 is common when no valid path is hit, still means the
                # gateway is alive.
                if resp.status_code >= 500:
                    logger.warning(
                        "Gateway unhealthy (HTTP %d): %s", resp.status_code, url
                    )
                    return False
            except requests.RequestException:
                logger.warning("Gateway unreachable: %s", url)
                return False

        return True
