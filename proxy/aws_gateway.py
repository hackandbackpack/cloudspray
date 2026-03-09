"""AWS API Gateway proxy provider -- the Fireprox technique for IP rotation.

This is the primary proxy backend for CloudSpray. It creates ephemeral AWS
API Gateway REST APIs that act as reverse proxies to the target server
(typically login.microsoftonline.com). Each request through the gateway
exits from a different IP in AWS's pool, defeating IP-based rate limiting
and blocking.

How Fireprox works, step by step:
    1. A REST API is created in AWS API Gateway with an HTTP_PROXY integration
       pointing at the target URL (e.g., https://login.microsoftonline.com).
    2. A greedy path resource {proxy+} is configured to capture any URL path
       and pass it through to the backend.
    3. The API is deployed to a "proxy" stage, giving us an invoke URL like:
       https://abc123.execute-api.us-east-1.amazonaws.com/proxy
    4. When we send a request to that invoke URL, API Gateway forwards it to
       Microsoft's server. The source IP is an AWS IP, not ours.
    5. Each request may get a different AWS IP from the pool, providing
       natural IP rotation without any additional infrastructure.

Multi-region support improves IP diversity further -- creating gateways in
us-east-1, us-west-2, eu-west-1, etc. means requests come from IP ranges
across different AWS data centers.

After the spray operation, all created API Gateways are deleted via teardown()
to avoid leaving orphaned resources in the AWS account.

Dependencies:
    boto3 is required but lazily imported so the rest of the codebase doesn't
    depend on it when using other proxy backends.
"""

import logging

import requests

from cloudspray.proxy.base import ProxyProvider
from cloudspray.utils import random_suffix

logger = logging.getLogger(__name__)


def _require_boto3():
    """Lazy-import boto3, raising a clear error if it is not installed.

    Returns:
        The boto3 module.

    Raises:
        ImportError: If boto3 is not installed, with install instructions.
    """
    try:
        import boto3  # noqa: F811

        return boto3
    except ImportError:
        raise ImportError(
            "boto3 is required for AWS API Gateway proxy support. "
            "Install it with: pip install boto3"
        ) from None


class AWSGatewayProvider(ProxyProvider):
    """AWS API Gateway proxy provider implementing the Fireprox technique.

    Creates REST API Gateways with HTTP_PROXY integration pointing at the
    target URL (e.g., login.microsoftonline.com). AWS assigns a different
    source IP from its pool for each request that passes through the gateway,
    effectively giving us free IP rotation.

    Gateways are created across multiple AWS regions for greater IP diversity.
    Requests are distributed across all gateways using round-robin selection,
    so consecutive requests hit different regions and get different IPs.

    Lifecycle:
        1. __init__() stores AWS credentials and desired regions
        2. setup() creates one API Gateway per region (tracked for cleanup)
        3. get_proxy_url() returns gateway invoke URLs in round-robin order
        4. teardown() deletes all created API Gateways

    Attributes:
        _access_key: AWS IAM access key ID.
        _secret_key: AWS IAM secret access key.
        _regions: AWS regions to deploy gateways in (e.g., ["us-east-1"]).
        _gateway_urls: Invoke URLs of successfully created gateways.
        _api_ids: Tuples of (region, api_id) for teardown tracking.
        _round_robin_index: Counter for cycling through gateway URLs.
    """

    def __init__(self, access_key: str, secret_key: str, regions: list[str]):
        """Initialize the provider with AWS credentials and target regions.

        Args:
            access_key: AWS IAM access key ID with API Gateway permissions.
            secret_key: AWS IAM secret access key.
            regions: List of AWS region slugs to create gateways in
                (e.g., ["us-east-1", "us-west-2", "eu-west-1"]). More
                regions means greater IP diversity but slower setup.
        """
        self._access_key = access_key
        self._secret_key = secret_key
        self._regions = regions
        self._gateway_urls: list[str] = []
        self._api_ids: list[tuple[str, str]] = []  # (region, api_id) for teardown
        self._round_robin_index = 0

    @property
    def name(self) -> str:
        return "aws-api-gateway"

    def setup(self, target_url: str) -> None:
        """Create REST API Gateways in each configured region.

        For each region, this method:
            1. Creates a new REST API with a REGIONAL endpoint
            2. Adds a greedy path resource {proxy+} that captures all URL paths
            3. Configures an ANY method with HTTP_PROXY integration so all HTTP
               methods (GET, POST, etc.) are forwarded to the target
            4. Maps the {proxy+} path variable through to the integration URI
               so paths like /common/oauth2/token are preserved
            5. Deploys the API to a "proxy" stage, producing an invoke URL

        Each gateway is tracked in _api_ids immediately after creation so that
        teardown() can clean it up even if later steps in setup fail.

        Args:
            target_url: The backend URL to proxy to
                (e.g., "https://login.microsoftonline.com").

        Raises:
            RuntimeError: If no gateways could be created in any region.
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
                # Step 1: Create the REST API resource in this region.
                # REGIONAL endpoint type means it's not deployed to CloudFront,
                # keeping the setup simpler and faster.
                api_response = client.create_rest_api(
                    name=api_name,
                    description="HTTP proxy integration",
                    endpointConfiguration={"types": ["REGIONAL"]},
                )
                api_id = api_response["id"]

                # Track immediately so teardown can clean up on later failures
                self._api_ids.append((region, api_id))

                # Step 2: Every REST API starts with a root "/" resource.
                # We need its ID to create child resources under it.
                resources = client.get_resources(restApiId=api_id)
                root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")

                # Step 3: Create a greedy path resource {proxy+} under root.
                # The "+" makes it greedy -- it captures the entire remaining
                # path (e.g., /common/oauth2/token) as a single variable.
                proxy_resource = client.create_resource(
                    restApiId=api_id,
                    parentId=root_id,
                    pathPart="{proxy+}",
                )
                resource_id = proxy_resource["id"]

                # Step 4: Create an ANY method (accepts all HTTP methods) with
                # no authorization. The requestParameters declaration tells
                # API Gateway that {proxy} is a path parameter.
                client.put_method(
                    restApiId=api_id,
                    resourceId=resource_id,
                    httpMethod="ANY",
                    authorizationType="NONE",
                    requestParameters={"method.request.path.proxy": True},
                )

                # Step 5: Configure HTTP_PROXY integration. This tells API
                # Gateway to forward the request to target_url/{proxy}, where
                # {proxy} is replaced with whatever path the client sent.
                # For example, a request to <gateway>/proxy/common/oauth2/token
                # gets forwarded to login.microsoftonline.com/common/oauth2/token.
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

                # Step 6: Deploy to a stage called "proxy". The stage name
                # becomes part of the invoke URL path.
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
        """Return the next gateway invoke URL using round-robin selection.

        Each call advances the index, so consecutive calls cycle through all
        available gateways across regions. This distributes requests evenly
        and maximizes IP diversity.

        Returns:
            An API Gateway invoke URL like:
            https://abc123.execute-api.us-east-1.amazonaws.com/proxy

        Raises:
            RuntimeError: If setup() has not been called or no gateways exist.
        """
        if not self._gateway_urls:
            raise RuntimeError("No gateway URLs available. Call setup() first.")

        url = self._gateway_urls[self._round_robin_index % len(self._gateway_urls)]
        self._round_robin_index += 1
        return url

    def teardown(self) -> None:
        """Delete all created REST APIs across all regions.

        Iterates through every (region, api_id) pair tracked during setup and
        deletes each API Gateway. Failures are logged but do not prevent
        cleanup of remaining gateways. All internal state is reset afterward.
        """
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
        """Verify all gateways are reachable by sending a GET to each invoke URL.

        A gateway is considered healthy if it returns any HTTP status below 500.
        Status codes like 403 or 404 are expected when hitting the base invoke
        URL without a valid path -- they still prove the gateway itself is
        accepting connections and forwarding to the backend.

        Returns:
            True if all gateways respond with status < 500, False if any
            gateway is unreachable or returns a server error.
        """
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
