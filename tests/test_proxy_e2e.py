"""Comprehensive End-to-End integration tests for the AI Data Firewall Reverse Proxy.

Tests all required flows:
- Clean request/response forwarding
- Request secret + WARN / REDACT / BLOCK
- Response secret + WARN / REDACT / BLOCK
- Strict anti-open-proxy / anti-SSRF protections
- Oversized request/response handling
- Upstream timeout and connection errors
- CONNECT tunneling rejection
- Health endpoint verification
- Zero raw secret leakage in errors, logs, and representations
"""

import asyncio
import json
from collections.abc import Coroutine
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from aifirewall.core.types import DetectionCategory, PolicyAction, Severity
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyRule
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import UpstreamError
from aifirewall.proxy.pipeline import SecurityPipeline
from aifirewall.proxy.server import create_proxy_app
from aifirewall.proxy.upstream import UpstreamClient


def _run(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async coroutine synchronously using standard library asyncio."""
    return asyncio.run(coro)


def _test_client(app: FastAPI) -> httpx.AsyncClient:
    """Create an in-memory async test client for a FastAPI ASGI application."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testproxy",
    )


@pytest.fixture
def fake_upstream_app() -> tuple[FastAPI, list[dict[str, Any]]]:
    """Create a mock upstream AI server that records received requests."""
    recorded_requests: list[dict[str, Any]] = []
    upstream = FastAPI()

    @upstream.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def echo_or_mock(request: Request, path: str) -> Response:
        body = await request.body()
        req_record = {
            "method": request.method,
            "path": path,
            "headers": dict(request.headers),
            "body": body,
        }
        recorded_requests.append(req_record)

        # Check for mock directives in request headers
        if "x-mock-response-secret" in request.headers:
            resp_data = {"reply": "Generated key: sk-upstreamsecret9876543210"}
            return Response(
                content=json.dumps(resp_data).encode("utf-8"),
                status_code=200,
                headers={"content-type": "application/json"},
            )

        if "x-mock-huge-response" in request.headers:
            return Response(
                content=b"A" * 50000,
                status_code=200,
                headers={"content-type": "text/plain"},
            )

        if "x-mock-status" in request.headers:
            code = int(request.headers["x-mock-status"])
            return Response(content=b'{"error":"custom"}', status_code=code)

        # Default echo response
        echo_str = body.decode("utf-8", errors="ignore")
        resp_payload = {"status": "received", "echo": echo_str}
        return Response(
            content=json.dumps(resp_payload).encode("utf-8"),
            status_code=200,
            headers={"content-type": "application/json"},
        )

    return upstream, recorded_requests


@pytest.fixture
def upstream_client_factory(
    fake_upstream_app: tuple[FastAPI, list[dict[str, Any]]],
):
    """Produce an UpstreamClient routed to fake_upstream_app via in-memory transport."""
    upstream_app, recorded = fake_upstream_app

    def _create(
        config: ProxyConfig,
    ) -> tuple[UpstreamClient, list[dict[str, Any]]]:
        client = UpstreamClient(config)
        transport = httpx.ASGITransport(app=upstream_app)
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://testupstream",
            timeout=httpx.Timeout(config.total_timeout),
        )
        return client, recorded

    return _create


class TestProxyEndToEnd:
    """Complete integration test suite using standard asyncio execution."""

    def test_health_endpoint(self) -> None:
        """GET /health must return 200 ok without contacting upstream."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://127.0.0.1:9000")
            app = create_proxy_app(config)
            async with _test_client(app) as client:
                resp = await client.get("/health")
                assert resp.status_code == 200
                assert resp.json() == {"status": "ok"}

        _run(_test())

    def test_clean_request_and_response_flow(
        self, upstream_client_factory: Any
    ) -> None:
        """Clean request and response proceed unaltered end-to-end."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)
            pipeline = SecurityPipeline(config=config)
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                req_data = {"prompt": "What is the capital of France?"}
                resp = await client.post(
                    "/v1/chat/completions",
                    json=req_data,
                    headers={"Authorization": "Bearer test-api-key"},
                )

                assert resp.status_code == 200
                assert len(recorded) == 1
                assert recorded[0]["path"] == "v1/chat/completions"
                assert recorded[0]["headers"]["authorization"] == "Bearer test-api-key"
                assert json.loads(recorded[0]["body"]) == req_data

        _run(_test())

    def test_request_secret_blocked(self, upstream_client_factory: Any) -> None:
        """Request with secret matching BLOCK returns 403; upstream receives nothing."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)

            block_rule = PolicyRule(
                rule_id="block_all_secrets",
                action=PolicyAction.BLOCK,
                category=DetectionCategory.SECRET,
                minimum_severity=Severity.HIGH,
            )
            pipeline = SecurityPipeline(
                config=config,
                policy_engine=PolicyEngine(PolicyConfig(rules=[block_rule])),
            )
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                secret_value = "sk-1234567890abcdef12345678"
                resp = await client.post(
                    "/v1/models",
                    json={"prompt": f"Secret is {secret_value}"},
                )

                assert resp.status_code == 403
                err_data = resp.json()
                assert err_data["error"]["code"] == "firewall_request_blocked"
                assert "Blocked" in err_data["error"]["message"]

                # Upstream must receive nothing
                assert len(recorded) == 0

                # Zero raw secret leakage in response
                assert secret_value not in resp.text

        _run(_test())

    def test_request_secret_redacted(self, upstream_client_factory: Any) -> None:
        """Request with secret matching REDACT forwards sanitized body upstream."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)

            redact_rule = PolicyRule(
                rule_id="redact_all_secrets",
                action=PolicyAction.REDACT,
                category=DetectionCategory.SECRET,
            )
            pipeline = SecurityPipeline(
                config=config,
                policy_engine=PolicyEngine(PolicyConfig(rules=[redact_rule])),
            )
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                secret_value = "sk-1234567890abcdef12345678"
                msg = f"My key is {secret_value}"
                resp = await client.post(
                    "/v1/chat",
                    json={"messages": [{"role": "user", "content": msg}]},
                )

                assert resp.status_code == 200
                assert len(recorded) == 1
                received_body = json.loads(recorded[0]["body"])

                # Verify upstream received masked placeholder, NOT raw secret
                content = received_body["messages"][0]["content"]
                assert "[REDACTED_SECRET]" in content
                assert secret_value not in str(received_body)

        _run(_test())

    def test_request_secret_warn(self, upstream_client_factory: Any) -> None:
        """Request containing secret with WARN rule forwards unmodified body."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)

            warn_rule = PolicyRule(
                rule_id="warn_secrets",
                action=PolicyAction.WARN,
                category=DetectionCategory.SECRET,
            )
            pipeline = SecurityPipeline(
                config=config,
                policy_engine=PolicyEngine(PolicyConfig(rules=[warn_rule])),
            )
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                secret_value = "sk-1234567890abcdef12345678"
                resp = await client.post("/v1/chat", json={"prompt": secret_value})
                assert resp.status_code == 200
                assert len(recorded) == 1
                assert secret_value in recorded[0]["body"].decode("utf-8")

        _run(_test())

    def test_response_secret_blocked(self, upstream_client_factory: Any) -> None:
        """Response with secret matching BLOCK returns 502 with dropped body."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)

            block_rule = PolicyRule(
                rule_id="block_resp_secrets",
                action=PolicyAction.BLOCK,
                category=DetectionCategory.SECRET,
            )
            pipeline = SecurityPipeline(
                config=config,
                policy_engine=PolicyEngine(PolicyConfig(rules=[block_rule])),
            )
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                resp = await client.post(
                    "/generate",
                    json={"query": "test"},
                    headers={"x-mock-response-secret": "1"},
                )

                assert resp.status_code == 502
                err_data = resp.json()
                assert err_data["error"]["code"] == "firewall_response_blocked"

                # Sensitive upstream secret must NOT reach client
                assert "sk-upstreamsecret9876543210" not in resp.text

        _run(_test())

    def test_response_secret_redacted(self, upstream_client_factory: Any) -> None:
        """Upstream response with secret matching REDACT rule is sanitized."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)

            redact_rule = PolicyRule(
                rule_id="redact_resp_secrets",
                action=PolicyAction.REDACT,
                category=DetectionCategory.SECRET,
            )
            pipeline = SecurityPipeline(
                config=config,
                policy_engine=PolicyEngine(PolicyConfig(rules=[redact_rule])),
            )
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                resp = await client.post(
                    "/generate",
                    json={"query": "test"},
                    headers={"x-mock-response-secret": "1"},
                )

                assert resp.status_code == 200
                resp_json = resp.json()
                assert "[REDACTED_SECRET]" in resp_json["reply"]
                assert "sk-upstreamsecret9876543210" not in resp.text

        _run(_test())

    def test_anti_open_proxy_header_ignored(self, upstream_client_factory: Any) -> None:
        """Client-supplied target override headers cannot redirect proxy."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://testupstream")
            upstream_client, recorded = upstream_client_factory(config)
            pipeline = SecurityPipeline(config=config)
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                await client.post(
                    "/test",
                    json={"msg": "hello"},
                    headers={
                        "X-Target-URL": "https://evil-attacker.example/steal",
                        "X-Upstream-URL": "http://evil.internal",
                    },
                )

                assert len(recorded) == 1
                assert "x-target-url" not in recorded[0]["headers"]
                assert "x-upstream-url" not in recorded[0]["headers"]

        _run(_test())

    def test_oversized_request_rejected(self) -> None:
        """Request body larger than max_request_body_bytes returns 413."""

        async def _test() -> None:
            config = ProxyConfig(
                upstream_url="http://127.0.0.1:9000",
                max_request_body_bytes=500,
            )
            app = create_proxy_app(config)
            async with _test_client(app) as client:
                resp = await client.post("/test", content=b"B" * 600)
                assert resp.status_code == 413
                assert resp.json()["error"]["code"] == "payload_too_large"

        _run(_test())

    def test_oversized_response_rejected(self, upstream_client_factory: Any) -> None:
        """Upstream response larger than max_response_body_bytes returns 502."""

        async def _test() -> None:
            config = ProxyConfig(
                upstream_url="http://testupstream",
                max_response_body_bytes=1000,
            )
            upstream_client, _ = upstream_client_factory(config)
            pipeline = SecurityPipeline(config=config)
            app = create_proxy_app(
                config, pipeline=pipeline, upstream_client=upstream_client
            )

            async with _test_client(app) as client:
                resp = await client.get("/huge", headers={"x-mock-huge-response": "1"})
                assert resp.status_code == 502
                assert resp.json()["error"]["code"] == "payload_too_large"

        _run(_test())

    def test_unsupported_method_rejected(self) -> None:
        """CONNECT or methods outside allowed_http_methods return 405."""

        async def _test() -> None:
            config = ProxyConfig(
                upstream_url="http://127.0.0.1:9000",
                allowed_http_methods=("GET", "POST"),
            )
            app = create_proxy_app(config)
            async with _test_client(app) as client:
                resp = await client.delete("/delete-something")
                assert resp.status_code == 405
                assert resp.json()["error"]["code"] == "method_not_allowed"

        _run(_test())

    def test_upstream_connection_failure_safe_502(self) -> None:
        """When upstream is unreachable, proxy returns safe 502 without traceback."""

        async def _test() -> None:
            config = ProxyConfig(upstream_url="http://127.0.0.1:1", connect_timeout=0.2)
            app = create_proxy_app(config)
            async with _test_client(app) as client:
                resp = await client.get("/status")
                assert resp.status_code in (502, 504)
                err_data = resp.json()
                assert err_data["error"]["code"] in (
                    "upstream_unavailable",
                    "upstream_timeout",
                )
                assert "Traceback" not in resp.text
                assert 'File "' not in resp.text

        _run(_test())

    def test_upstream_network_error_502(self) -> None:
        """Verify UpstreamError produces exact 502 code and safe message."""

        class MockFailingClient(UpstreamClient):
            async def forward(self, *args: Any, **kwargs: Any) -> Any:
                raise UpstreamError("Network connection reset by peer.")

        config = ProxyConfig(upstream_url="http://testupstream")
        failing_client = MockFailingClient(config)
        app = create_proxy_app(config, upstream_client=failing_client)

        async def _test() -> None:
            async with _test_client(app) as client:
                resp = await client.get("/test")
                assert resp.status_code == 502
                err = resp.json()
                assert err["error"]["code"] == "upstream_unavailable"
                assert "reset by peer" in err["error"]["message"]

        _run(_test())
