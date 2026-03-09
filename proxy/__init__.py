"""Proxy module for IP rotation during password spray operations.

CloudSpray needs to send many authentication requests to Microsoft's login
servers (login.microsoftonline.com). If all requests come from the same IP
address, Microsoft will quickly detect and block the activity. This module
solves that problem by routing each request through a different IP address.

The primary technique is called "Fireprox" -- creating AWS API Gateway
endpoints that act as reverse proxies. When a request goes through an API
Gateway, AWS assigns it a source IP from its own pool, so Microsoft sees a
different IP for each request. This is fundamentally different from a
traditional HTTP proxy: instead of setting proxy headers, we rewrite the
request URL itself to point at the API Gateway endpoint, which then forwards
the request to Microsoft on our behalf.

Three proxy backends are supported:
    - AWSGatewayProvider: The Fireprox technique. Creates ephemeral API Gateway
      REST APIs in one or more AWS regions. Best IP diversity, lowest cost.
    - AzureACIProvider: Deploys tinyproxy containers in Azure Container
      Instances. Each container gets its own public IP. Azure IPs blend well
      with legitimate M365 traffic since Microsoft owns them.
    - ProxyListProvider: Uses a static list of pre-existing HTTP/SOCKS5 proxies.
      No cloud infrastructure needed, but IP diversity depends on the list.

ProxyManager ties these together, handling round-robin selection across multiple
providers, health checking, cooldown for failed providers, and guaranteed
teardown of cloud resources via context manager support.

Typical usage::

    from cloudspray.proxy import ProxyManager, AWSGatewayProvider

    with ProxyManager() as mgr:
        mgr.add_provider(AWSGatewayProvider(key, secret, ["us-east-1"]))
        mgr.setup_all("https://login.microsoftonline.com")
        session = mgr.get_session()
        session.post(target_url, data=payload)
"""

from cloudspray.proxy.aws_gateway import AWSGatewayProvider
from cloudspray.proxy.azure_aci import AzureACIProvider
from cloudspray.proxy.base import ProxyProvider
from cloudspray.proxy.manager import ProxyManager
from cloudspray.proxy.proxy_list import ProxyListProvider

__all__ = [
    "AWSGatewayProvider",
    "AzureACIProvider",
    "ProxyManager",
    "ProxyListProvider",
    "ProxyProvider",
]
