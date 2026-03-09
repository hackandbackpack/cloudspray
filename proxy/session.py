import requests

from cloudspray.proxy.base import ProxyProvider


class FireproxSession(requests.Session):
    """Session that rewrites URLs to route through API Gateway proxies."""

    def __init__(self, provider: ProxyProvider, target_host: str) -> None:
        super().__init__()
        self.provider = provider
        self.target_host = target_host
        self.last_proxy_url: str = ""

    def request(self, method, url, **kwargs):
        target_prefix = f"https://{self.target_host}"
        if self.target_host in url:
            gateway_url = self.provider.get_proxy_url()
            self.last_proxy_url = gateway_url
            url = url.replace(target_prefix, gateway_url, 1)
        return super().request(method, url, **kwargs)
