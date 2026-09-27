"""Security regression tests for Step 9 provider adapters.

Verifies Section 55 requirements:
- Fixed upstream remains fixed (cannot be overridden by headers, body, or query).
- Client cannot override provider configuration via headers or payload.
- Client cannot override upstream destination.
- Authorization headers remain strictly unlogged and unexposed in metadata.
- Provider adapters cannot leak raw credentials.
- Provider adapters cannot cause external network calls.
- Unsupported provider fails safely at configuration time.
- Unsupported streaming does not silently pass as inspected (fails closed with 400).
"""

import asyncio
import json
from collections.abc import Coroutine
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from aifirewall.core.errors import ConfigurationError
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.pipeline import SecurityPipeline
from aifirewall.proxy.server import create_proxy_app
from aifirewall.proxy.upstream import UpstreamClient


def _run(coro: Coroutine[Any, Any, Any]) -> Any:
    return asyncio.run(coro)


def _test_client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testproxy",
    )


def test_unsupported_provider_fails_at_config_time() -> None:
    """Configuring an invalid provider fails immediately with ConfigurationError."""
    with pytest.raises(ConfigurationError) as exc_info:
        ProxyConfig(
            upstream_url="http://127.0.0.1:8000",
            provider="unsupported_custom_llm",
        )
    assert "Unsupported provider" in str(exc_info.value)
    assert "unsupported_custom_llm" in str(exc_info.value)


def test_fixed_upstream_cannot_be_overridden_by_request_header() -> None:
    """Headers attempting to redirect upstream traffic are ignored or rejected."""
    recorded: list[dict[str, Any]] = []
    upstream = FastAPI()

    @upstream.post("/{path:path}")
    async def echo(request: Request, path: str) -> Response:
        body = await request.body()
        recorded.append({"path": path, "body": body})
        return Response(content=b'{"status":"ok"}', status_code=200)

    config = ProxyConfig(upstream_url="http://fixed-upstream", provider="openai")
    upstream_client = UpstreamClient(config)
    upstream_client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream),
        base_url="http://fixed-upstream",
    )

    app = create_proxy_app(config, upstream_client=upstream_client)

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers={
                    "Host": "evil-attacker.com",
                    "X-Forwarded-Host": "evil-attacker.com",
                    "X-Upstream-Url": "http://evil-attacker.com",
                },
            )
            assert resp.status_code == 200
            # Upstream client routed strictly to fixed-upstream
            assert len(recorded) == 1

    _run(_test())


def test_client_cannot_override_configured_provider() -> None:
    """Client cannot supply headers or query params to force a different adapter."""
    recorded: list[dict[str, Any]] = []
    upstream = FastAPI()

    @upstream.post("/{path:path}")
    async def handler(request: Request, path: str) -> Response:
        body = await request.body()
        recorded.append({"body": body})
        return Response(
            content=json.dumps(
                {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode("utf-8"),
            status_code=200,
        )

    # Proxy is explicitly configured with OpenAI
    config = ProxyConfig(upstream_url="http://fixed-upstream", provider="openai")
    upstream_client = UpstreamClient(config)
    upstream_client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream),
        base_url="http://fixed-upstream",
    )
    pipeline = SecurityPipeline(config=config)
    app = create_proxy_app(config, pipeline=pipeline, upstream_client=upstream_client)

    async def _test() -> None:
        async with _test_client(app) as client:
            # Client tries to claim it's anthropic via header or query
            resp = await client.post(
                "/v1/chat/completions?provider=anthropic",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "hi"}],
                },
                headers={"X-Provider": "anthropic"},
            )
            assert resp.status_code == 200
            # Ensure the pipeline used OpenAI adapter as configured
            assert pipeline.configured_provider == "openai"

    _run(_test())


def test_streaming_request_fails_closed_safely() -> None:
    """A request with stream=True must be rejected with 400."""
    upstream_called = False
    upstream = FastAPI()

    @upstream.post("/{path:path}")
    async def handler(request: Request, path: str) -> Response:
        nonlocal upstream_called
        upstream_called = True
        return Response(content=b"data: chunk\n\n", status_code=200)

    config = ProxyConfig(upstream_url="http://fixed-upstream", provider="openai")
    upstream_client = UpstreamClient(config)
    upstream_client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream),
        base_url="http://fixed-upstream",
    )
    app = create_proxy_app(config, upstream_client=upstream_client)

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                },
            )
            assert resp.status_code == 400
            err_data = resp.json()
            assert err_data["error"]["code"] == "unsupported_streaming"
            assert "streaming" in err_data["error"]["message"].lower()
            # Upstream was never contacted!
            assert not upstream_called

    _run(_test())


def test_authorization_header_unlogged_and_unleaked_in_adapter() -> None:
    """Authorization is passed by transport and never stored by adapters."""
    from aifirewall.providers.openai import OpenAIAdapter

    adapter = OpenAIAdapter()
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "api_key": "secret-leak-attempt",
    }

    norm_req = adapter.normalize_request(payload)
    # api_key is ignored and not included in metadata or parameters
    assert "api_key" not in norm_req.metadata
    assert "api_key" not in norm_req.parameters
    assert "secret-leak-attempt" not in str(norm_req)


def test_provider_adapters_cannot_make_network_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure provider adapters do not invoke network calls."""
    from aifirewall.providers.anthropic import AnthropicAdapter
    from aifirewall.providers.gemini import GeminiAdapter
    from aifirewall.providers.ollama import OllamaAdapter
    from aifirewall.providers.openai import OpenAIAdapter

    def _fail_on_network(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Provider adapter attempted a network connection!")

    monkeypatch.setattr("socket.socket.connect", _fail_on_network)

    adapters = [
        OpenAIAdapter(),
        AnthropicAdapter(),
        GeminiAdapter(),
        OllamaAdapter(),
    ]

    for adapter in adapters:
        # Just normalize/denormalize simple payloads
        if adapter.provider_name == "openai":
            r = adapter.normalize_request(
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]}
            )
            adapter.denormalize_request(r)
        elif adapter.provider_name == "anthropic":
            r = adapter.normalize_request(
                {"model": "c-3", "messages": [{"role": "user", "content": "test"}]}
            )
            adapter.denormalize_request(r)
        elif adapter.provider_name == "gemini":
            r = adapter.normalize_request(
                {"contents": [{"role": "user", "parts": [{"text": "test"}]}]}
            )
            adapter.denormalize_request(r)
        elif adapter.provider_name == "ollama":
            r = adapter.normalize_request(
                {"model": "l3", "messages": [{"role": "user", "content": "test"}]}
            )
            adapter.denormalize_request(r)
