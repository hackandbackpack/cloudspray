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
        rewritten, was_rewritten = session._rewrite_url(original)

        assert rewritten == f"{GATEWAY}/common/oauth2/token"
        assert was_rewritten is True
        assert session.last_proxy_url == GATEWAY

    def test_http_url_is_rewritten(self) -> None:
        """This was the bug: http:// URLs passed the old 'in' check but the
        replace on 'https://' did nothing, sending the request directly to the
        target and revealing the operator's real IP."""
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        original = f"http://{TARGET_HOST}/common/oauth2/token"
        rewritten, was_rewritten = session._rewrite_url(original)

        assert rewritten == f"{GATEWAY}/common/oauth2/token"
        assert was_rewritten is True
        assert session.last_proxy_url == GATEWAY

    def test_unrelated_url_is_not_rewritten(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        original = "https://other-service.example.com/api/v1/data"
        rewritten, was_rewritten = session._rewrite_url(original)

        assert rewritten == original
        assert was_rewritten is False
        assert session.last_proxy_url == ""


class TestForwardedForHeader:
    """The gateway maps X-My-X-Forwarded-For over the X-Forwarded-For that API
    Gateway would otherwise fill with the operator's real IP. If the session
    does not send the header, the mapping has nothing to substitute."""

    def test_defaults_to_empty_suppressing_operator_ip(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        assert session.forwarded_for == ""

    def test_inherits_value_from_provider(self) -> None:
        provider = FakeProvider(GATEWAY)
        provider.forwarded_for = "203.0.113.7"
        session = FireproxSession(provider, TARGET_HOST)
        assert session.forwarded_for == "203.0.113.7"

    def test_explicit_value_wins_over_provider(self) -> None:
        provider = FakeProvider(GATEWAY)
        provider.forwarded_for = "203.0.113.7"
        session = FireproxSession(provider, TARGET_HOST, forwarded_for="")
        assert session.forwarded_for == ""

    def test_header_sent_on_proxied_request(self) -> None:
        """Captures what would go on the wire without making a real request."""
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        captured = {}

        def fake_send(request, **kwargs):
            captured["url"] = request.url
            captured["headers"] = dict(request.headers)
            raise _StopSend()

        session.send = fake_send
        try:
            session.post(f"https://{TARGET_HOST}/common/oauth2/token", data={"a": "b"})
        except _StopSend:
            pass

        assert captured["url"].startswith(GATEWAY)
        assert "X-My-X-Forwarded-For" in captured["headers"]

    def test_header_not_added_to_unproxied_request(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        captured = {}

        def fake_send(request, **kwargs):
            captured["headers"] = dict(request.headers)
            raise _StopSend()

        session.send = fake_send
        try:
            session.get("https://other-service.example.com/api")
        except _StopSend:
            pass

        assert "X-My-X-Forwarded-For" not in captured["headers"]

    def test_caller_headers_are_not_mutated(self) -> None:
        session = FireproxSession(FakeProvider(GATEWAY), TARGET_HOST)
        caller_headers = {"User-Agent": "test-agent"}

        def fake_send(request, **kwargs):
            raise _StopSend()

        session.send = fake_send
        try:
            session.get(f"https://{TARGET_HOST}/x", headers=caller_headers)
        except _StopSend:
            pass

        assert caller_headers == {"User-Agent": "test-agent"}


class _StopSend(Exception):
    """Aborts a request once its prepared form has been captured."""
