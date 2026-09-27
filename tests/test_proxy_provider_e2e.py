"""Local end-to-end integration tests for Provider Adapters through the Proxy Pipeline.

Verifies Section 66 requirement:
fake AI client
    ↓
AI Data Firewall proxy
    ↓
provider adapter
    ↓
security pipeline
    ↓
fake upstream

Tests all 8 required flows for each provider (OpenAI, Anthropic, Gemini, Ollama):
1. clean provider request
2. request secret + WARN
3. request secret + REDACT
4. request secret + BLOCK
5. clean provider response
6. response secret + WARN
7. response secret + REDACT
8. response secret + BLOCK

All tests run locally, offline, with zero external network access.
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
from aifirewall.proxy.pipeline import SecurityPipeline
from aifirewall.proxy.server import create_proxy_app
from aifirewall.proxy.upstream import UpstreamClient

SYNTHETIC_REQUEST_SECRET = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SYNTHETIC_RESPONSE_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _run(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _test_client(app: FastAPI) -> httpx.AsyncClient:
    """Create an in-memory async test client for a FastAPI ASGI application."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testproxy",
    )


# ---------------------------------------------------------------------------
# Provider-specific test fixtures and payload generators
# ---------------------------------------------------------------------------

PROVIDER_CONFIGS = {
    "openai": {
        "path": "/v1/chat/completions",
        "clean_req": {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "What is the capital of France?"}],
        },
        "secret_req": {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": f"My GitHub key is {SYNTHETIC_REQUEST_SECRET}",
                }
            ],
        },
        "clean_resp": {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "The capital is Paris.",
                    },
                    "finish_reason": "stop",
                }
            ],
        },
        "secret_resp": {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"The access key is {SYNTHETIC_RESPONSE_SECRET}",
                    },
                    "finish_reason": "stop",
                }
            ],
        },
    },
    "anthropic": {
        "path": "/v1/messages",
        "clean_req": {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "What is the capital of France?"}],
        },
        "secret_req": {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": f"My GitHub key is {SYNTHETIC_REQUEST_SECRET}",
                }
            ],
        },
        "clean_resp": {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [{"type": "text", "text": "The capital is Paris."}],
            "stop_reason": "end_turn",
        },
        "secret_resp": {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [
                {
                    "type": "text",
                    "text": f"The access key is {SYNTHETIC_RESPONSE_SECRET}",
                }
            ],
            "stop_reason": "end_turn",
        },
    },
    "gemini": {
        "path": "/v1beta/models/gemini-1.5-flash:generateContent",
        "clean_req": {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": "What is the capital of France?"}],
                }
            ]
        },
        "secret_req": {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"My GitHub key is {SYNTHETIC_REQUEST_SECRET}"}],
                }
            ]
        },
        "clean_resp": {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [{"text": "The capital is Paris."}],
                    },
                    "finishReason": "STOP",
                    "index": 0,
                }
            ],
            "modelVersion": "gemini-1.5-flash",
        },
        "secret_resp": {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {"text": f"The access key is {SYNTHETIC_RESPONSE_SECRET}"}
                        ],
                    },
                    "finishReason": "STOP",
                    "index": 0,
                }
            ],
            "modelVersion": "gemini-1.5-flash",
        },
    },
    "ollama": {
        "path": "/api/chat",
        "clean_req": {
            "model": "llama3",
            "messages": [{"role": "user", "content": "What is the capital of France?"}],
        },
        "secret_req": {
            "model": "llama3",
            "messages": [
                {
                    "role": "user",
                    "content": f"My GitHub key is {SYNTHETIC_REQUEST_SECRET}",
                }
            ],
        },
        "clean_resp": {
            "model": "llama3",
            "message": {"role": "assistant", "content": "The capital is Paris."},
            "done": True,
            "done_reason": "stop",
        },
        "secret_resp": {
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": f"The access key is {SYNTHETIC_RESPONSE_SECRET}",
            },
            "done": True,
            "done_reason": "stop",
        },
    },
}


def _create_fake_upstream(
    clean_resp: dict[str, Any], secret_resp: dict[str, Any]
) -> tuple[FastAPI, list[dict[str, Any]]]:
    """Create a mock upstream server recording incoming requests."""
    recorded_requests: list[dict[str, Any]] = []
    upstream = FastAPI()

    @upstream.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def handler(request: Request, path: str) -> Response:
        body = await request.body()
        recorded_requests.append(
            {
                "method": request.method,
                "path": path,
                "headers": dict(request.headers),
                "body": body,
            }
        )

        if "x-mock-secret-response" in request.headers:
            return Response(
                content=json.dumps(secret_resp).encode("utf-8"),
                status_code=200,
                headers={"content-type": "application/json"},
            )

        return Response(
            content=json.dumps(clean_resp).encode("utf-8"),
            status_code=200,
            headers={"content-type": "application/json"},
        )

    return upstream, recorded_requests


def _build_proxy_setup(
    provider: str,
    rules: list[PolicyRule],
    clean_resp: dict[str, Any],
    secret_resp: dict[str, Any],
) -> tuple[FastAPI, list[dict[str, Any]]]:
    """Build proxy app and in-memory upstream connection."""
    upstream_app, recorded = _create_fake_upstream(clean_resp, secret_resp)
    config = ProxyConfig(
        upstream_url="http://testupstream",
        provider=provider,
    )
    upstream_client = UpstreamClient(config)
    upstream_client._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream_app),
        base_url="http://testupstream",
    )

    policy_engine = PolicyEngine(PolicyConfig(rules=rules))
    pipeline = SecurityPipeline(config=config, policy_engine=policy_engine)
    app = create_proxy_app(config, pipeline=pipeline, upstream_client=upstream_client)
    return app, recorded


# ---------------------------------------------------------------------------
# Test all 8 flows across all 4 providers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_1_clean_request(provider: str) -> None:
    """1. Clean provider request passes unaltered and receives clean response."""
    pinfo = PROVIDER_CONFIGS[provider]
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(pinfo["path"], json=pinfo["clean_req"])
            assert resp.status_code == 200
            assert len(recorded) == 1
            received_body = json.loads(recorded[0]["body"])
            assert "France" in json.dumps(received_body)
            assert "Paris" in resp.text

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_2_request_secret_warn(provider: str) -> None:
    """2. Request with secret + WARN passes unaltered upstream; 200 returned."""
    pinfo = PROVIDER_CONFIGS[provider]
    warn_rule = PolicyRule(
        rule_id="warn_secret",
        action=PolicyAction.WARN,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[warn_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(pinfo["path"], json=pinfo["secret_req"])
            assert resp.status_code == 200
            assert len(recorded) == 1
            # Unaltered request body forwarded under WARN
            assert SYNTHETIC_REQUEST_SECRET in recorded[0]["body"].decode("utf-8")

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_3_request_secret_redact(provider: str) -> None:
    """3. Request with secret + REDACT forwards sanitized provider body."""
    pinfo = PROVIDER_CONFIGS[provider]
    redact_rule = PolicyRule(
        rule_id="redact_secret",
        action=PolicyAction.REDACT,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[redact_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(pinfo["path"], json=pinfo["secret_req"])
            assert resp.status_code == 200
            assert len(recorded) == 1

            received_body_str = recorded[0]["body"].decode("utf-8")
            # Secret must be strictly absent from upstream request
            assert SYNTHETIC_REQUEST_SECRET not in received_body_str
            # Semantic placeholder must be present in the provider-specific payload
            assert "[REDACTED_SECRET]" in received_body_str

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_4_request_secret_block(provider: str) -> None:
    """4. Request with secret + BLOCK returns 403; upstream receives nothing."""
    pinfo = PROVIDER_CONFIGS[provider]
    block_rule = PolicyRule(
        rule_id="block_secret",
        action=PolicyAction.BLOCK,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[block_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(pinfo["path"], json=pinfo["secret_req"])
            assert resp.status_code == 403
            err_data = resp.json()
            assert err_data["error"]["code"] == "firewall_request_blocked"
            assert "Blocked" in err_data["error"]["message"]
            # Upstream received nothing
            assert len(recorded) == 0

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_5_clean_response(provider: str) -> None:
    """5. Clean provider response returns 200 to client."""
    pinfo = PROVIDER_CONFIGS[provider]
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(pinfo["path"], json=pinfo["clean_req"])
            assert resp.status_code == 200
            assert "Paris" in resp.text

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_6_response_secret_warn(provider: str) -> None:
    """6. Response with secret + WARN returns 200 to client without blocking."""
    pinfo = PROVIDER_CONFIGS[provider]
    warn_rule = PolicyRule(
        rule_id="warn_resp_secret",
        action=PolicyAction.WARN,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[warn_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(
                pinfo["path"],
                json=pinfo["clean_req"],
                headers={"x-mock-secret-response": "1"},
            )
            assert resp.status_code == 200
            assert SYNTHETIC_RESPONSE_SECRET in resp.text

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_7_response_secret_redact(provider: str) -> None:
    """7. Response with secret + REDACT returns 200 sanitized; secret absent."""
    pinfo = PROVIDER_CONFIGS[provider]
    redact_rule = PolicyRule(
        rule_id="redact_resp_secret",
        action=PolicyAction.REDACT,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[redact_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(
                pinfo["path"],
                json=pinfo["clean_req"],
                headers={"x-mock-secret-response": "1"},
            )
            assert resp.status_code == 200
            resp_text = resp.text
            # Secret must be strictly absent
            assert SYNTHETIC_RESPONSE_SECRET not in resp_text
            # Redaction placeholder must be present
            assert "[REDACTED_SECRET]" in resp_text

    _run(_test())


@pytest.mark.parametrize("provider", ["openai", "anthropic", "gemini", "ollama"])
def test_e2e_flow_8_response_secret_block(provider: str) -> None:
    """8. Response with secret + BLOCK returns 502; sensitive response suppressed."""
    pinfo = PROVIDER_CONFIGS[provider]
    block_rule = PolicyRule(
        rule_id="block_resp_secret",
        action=PolicyAction.BLOCK,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    app, recorded = _build_proxy_setup(
        provider=provider,
        rules=[block_rule],
        clean_resp=pinfo["clean_resp"],
        secret_resp=pinfo["secret_resp"],
    )

    async def _test() -> None:
        async with _test_client(app) as client:
            resp = await client.post(
                pinfo["path"],
                json=pinfo["clean_req"],
                headers={"x-mock-secret-response": "1"},
            )
            assert resp.status_code == 502
            err_data = resp.json()
            assert err_data["error"]["code"] == "firewall_response_blocked"
            assert "Blocked" in err_data["error"]["message"]
            # Sensitive response secret must NOT reach client
            assert SYNTHETIC_RESPONSE_SECRET not in resp.text

    _run(_test())
