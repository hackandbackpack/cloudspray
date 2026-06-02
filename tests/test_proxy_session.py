"""Tests for FireproxSession URL rewriting."""

from cloudspray.proxy.base import ProxyProvider
from cloudspray.proxy.session import FireproxSession


class FakeProvider(ProxyProvider):
    """Minimal provider that returns a fixed gateway URL."""

    def __init__(self, gateway_url: str = "https://abc123.execute-api.us-east-1.amazonaws.com/proxy") -> None:
        self._gateway_url = gateway_url

    def setup(self, target_url: str) -> None:
        pass

    def get_proxy_url(self) -> str:
        return self._gateway_url

    def teardown(self) -> None:
        pass

    def health_check(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "fake"


TARGET_HOST = "login.microsoftonline.com"
GATEWAY = "https://abc123.execute-api.us-east-1.amazonaws.com/proxy"


class TestRewriteUrl:
    """Tests for _rewrite_url covering both schemes and non-matching URLs."""

    def test_https_url_is_rewritten(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        original = f"https://{TARGET_HOST}/common/oauth2/token"
        rewritten = session._rewrite_url(original)

        assert rewritten == f"{GATEWAY}/common/oauth2/token"
        assert session.last_proxy_url == GATEWAY

    def test_http_url_is_rewritten(self) -> None:
        """This was the bug: http:// URLs passed the old 'in' check but the
        replace on 'https://' did nothing, sending the request directly to the
        target and revealing the operator's real IP."""
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        original = f"http://{TARGET_HOST}/common/oauth2/token"
        rewritten = session._rewrite_url(original)

        assert rewritten == f"{GATEWAY}/common/oauth2/token"
        assert session.last_proxy_url == GATEWAY

    def test_unrelated_url_is_not_rewritten(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        original = "https://other-service.example.com/api/v1/data"
        rewritten = session._rewrite_url(original)

        assert rewritten == original
        assert session.last_proxy_url == ""
