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

# API Gateway inserts its own X-Forwarded-For containing the caller's real IP.
# Declaring a client-supplied header and mapping it over the top is how the
# Fireprox technique keeps the operator's address out of the forwarded request.
FORWARDED_FOR_HEADER = "X-My-X-Forwarded-For"
FORWARDED_FOR_METHOD_PARAM = f"method.request.header.{FORWARDED_FOR_HEADER}"
FORWARDED_FOR_INTEGRATION_PARAM = "integration.request.header.X-Forwarded-For"

# API Gateway stamps this header on responses it generates itself (throttling,
# missing auth token, bad configuration). Its presence proves the request never
# reached the backend, which is what distinguishes a live proxy from a broken one.
_APIGW_ERROR_HEADER = "x-amzn-ErrorType"


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

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        regions: list[str],
        forwarded_for: str = "",
    ):
        """Initialize the provider with AWS credentials and target regions.

        Args:
            access_key: AWS IAM access key ID with API Gateway permissions.
            secret_key: AWS IAM secret access key.
            regions: List of AWS region slugs to create gateways in
                (e.g., ["us-east-1", "us-west-2", "eu-west-1"]). More
                regions means greater IP diversity but slower setup.
            forwarded_for: Value sent in ``X-My-X-Forwarded-For``, which the
                gateway maps over the X-Forwarded-For it would otherwise fill
                with the operator's real IP. Empty (the default) suppresses the
                address without claiming to be some unrelated third party.
        """
        self._access_key = access_key
        self._secret_key = secret_key
        self._regions = regions
        self._forwarded_for = forwarded_for
        self._gateway_urls: list[str] = []
        self._api_ids: list[tuple[str, str]] = []  # (region, api_id) for teardown
        self._round_robin_index = 0
        self._failed_regions: list[str] = []

    @property
    def name(self) -> str:
        return "aws-api-gateway"

    @property
    def gateway_count(self) -> int:
        """Number of gateways that were created successfully."""
        return len(self._gateway_urls)

    @property
    def failed_regions(self) -> list[str]:
        """Regions where gateway creation failed, for operator visibility."""
        return list(self._failed_regions)

    @property
    def forwarded_for(self) -> str:
        """Value the session should send in ``X-My-X-Forwarded-For``."""
        return self._forwarded_for

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
                # API Gateway that {proxy} is a path parameter, and that we
                # may supply X-My-X-Forwarded-For (see step 5 for why).
                client.put_method(
                    restApiId=api_id,
                    resourceId=resource_id,
                    httpMethod="ANY",
                    authorizationType="NONE",
                    requestParameters={
                        "method.request.path.proxy": True,
                        FORWARDED_FOR_METHOD_PARAM: False,
                    },
                )

                # Step 5: Configure HTTP_PROXY integration. This tells API
                # Gateway to forward the request to target_url/{proxy}, where
                # {proxy} is replaced with whatever path the client sent.
                # For example, a request to <gateway>/proxy/common/oauth2/token
                # gets forwarded to login.microsoftonline.com/common/oauth2/token.
                #
                # The X-Forwarded-For mapping is the part that actually makes
                # this anonymous. Left alone, API Gateway appends the caller's
                # real source IP to X-Forwarded-For before handing the request
                # to the backend, so the target sees straight through the proxy
                # even though the TCP connection comes from AWS. Overriding it
                # from a client-supplied header means we control the value.
                integration_uri = f"{target_url}/{{proxy}}"
                client.put_integration(
                    restApiId=api_id,
                    resourceId=resource_id,
                    httpMethod="ANY",
                    type="HTTP_PROXY",
                    integrationHttpMethod="ANY",
                    uri=integration_uri,
                    requestParameters={
                        "integration.request.path.proxy": "method.request.path.proxy",
                        FORWARDED_FOR_INTEGRATION_PARAM: FORWARDED_FOR_METHOD_PARAM,
                    },
                )

                # Step 6: Proxy the root path too. Without a method on "/", a
                # request to the bare invoke URL is answered by API Gateway
                # itself rather than the backend, which makes it impossible to
                # tell a working gateway from a misconfigured one.
                client.put_method(
                    restApiId=api_id,
                    resourceId=root_id,
                    httpMethod="ANY",
                    authorizationType="NONE",
                    requestParameters={FORWARDED_FOR_METHOD_PARAM: False},
                )
                client.put_integration(
                    restApiId=api_id,
                    resourceId=root_id,
                    httpMethod="ANY",
                    type="HTTP_PROXY",
                    integrationHttpMethod="ANY",
                    uri=target_url,
                    requestParameters={
                        FORWARDED_FOR_INTEGRATION_PARAM: FORWARDED_FOR_METHOD_PARAM,
                    },
                )

                # Step 7: Deploy to a stage called "proxy". The stage name
                # becomes part of the invoke URL path.
                client.create_deployment(restApiId=api_id, stageName="proxy")

                invoke_url = (
                    f"https://{api_id}.execute-api.{region}.amazonaws.com/proxy"
                )
                self._gateway_urls.append(invoke_url)
                logger.info("Created API Gateway %s in %s", api_id, region)

            except Exception:
                # Recorded so the caller can tell the operator that IP diversity
                # is lower than they asked for instead of failing silently.
                self._failed_regions.append(region)
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
        """Verify every gateway actually forwards to the backend.

        Checking only for "status < 500" is not enough: API Gateway answers a
        request it cannot route with its own 403, so a gateway whose integration
        is misconfigured looks identical to a working one. This sends a request
        through the proxy and rejects any response that API Gateway generated
        itself, identified by the ``x-amzn-ErrorType`` header.

        Returns:
            True only if every gateway returned a response that came from the
            backend. False if any gateway is unreachable, returns a server
            error, or answers from API Gateway itself.
        """
        if not self._gateway_urls:
            return False

        for url in self._gateway_urls:
            try:
                resp = requests.get(
                    f"{url}/",
                    timeout=10,
                    allow_redirects=False,
                    headers={FORWARDED_FOR_HEADER: self._forwarded_for},
                )
            except requests.RequestException:
                logger.warning("Gateway unreachable: %s", url)
                return False

            if resp.status_code >= 500:
                logger.warning("Gateway unhealthy (HTTP %d): %s", resp.status_code, url)
                return False

            # A response from API Gateway itself never touched the backend, so
            # the integration is wrong no matter how benign the status looks.
            if _APIGW_ERROR_HEADER in resp.headers:
                logger.warning(
                    "Gateway did not reach the backend (%s: %s): %s",
                    _APIGW_ERROR_HEADER,
                    resp.headers[_APIGW_ERROR_HEADER],
                    url,
                )
                return False

        return True
