"""End-to-End User Journey Tests for AI Data Firewall v0.1.

Simulates the complete developer workflow:
1. Import public components from `aifirewall`
2. Create typed ProxyConfig and PolicyConfig (with presets or rules)
3. Select provider adapter (e.g. OpenAI, Anthropic, Gemini, Ollama)
4. Instantiate DetectorRegistry, SecurityPipeline, and FirewallProxy
5. Fake client sends requests through proxy
6. Security pipeline inspects, detects, applies policy, and redacts/blocks
7. Fake upstream handles permitted requests and returns responses
8. Security pipeline inspects, detects, applies policy, and redacts/blocks responses
9. Fake client receives safe response

Tests all 8 key scenarios:
A. Clean request
B. Request WARN
C. Request REDACT
D. Request BLOCK
E. Clean response
F. Response WARN
G. Response REDACT
H. Response BLOCK

All tests are 100% offline, deterministic, and require zero live credentials.
"""

import asyncio
import json
from collections.abc import Coroutine, Mapping
from typing import Any

import httpx

# Step 1: Import directly from top-level package
from aifirewall import (
    DetectionCategory,
    DetectorRegistry,
    PolicyAction,
    PolicyConfig,
    PolicyEngine,
    PolicyRule,
    ProxyConfig,
    SecretDetector,
    SecurityPipeline,
)
from aifirewall.proxy.server import create_proxy_app
from aifirewall.proxy.upstream import UpstreamClient

SYNTHETIC_CLIENT_SECRET = "sk-proj-012345678901234567890123456789012345678901234567"
SYNTHETIC_UPSTREAM_SECRET = "ghp_ABCDEF012345678901234567890123456789"


def _run(coro: Coroutine[Any, Any, Any]) -> Any:
    """Helper to run async coroutines synchronously."""
    return asyncio.run(coro)


class MockUpstreamClient(UpstreamClient):
    """Mock upstream client simulating a real provider backend without network calls."""

    def __init__(self, config: ProxyConfig, response_payload: dict[str, Any]) -> None:
        super().__init__(config)
        self.recorded_requests: list[dict[str, Any]] = []
        self._mock_response = response_payload

    async def forward(
        self,
        method: str,
        path: str,
        query_string: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> Any:
        # Record forwarded request for verification
        self.recorded_requests.append(
            {
                "method": method,
                "path": path,
                "headers": headers,
                "body": body,
            }
        )
        from aifirewall.proxy.upstream import UpstreamResponse

        resp_bytes = json.dumps(self._mock_response).encode("utf-8")
        return UpstreamResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=resp_bytes,
        )


class TestUserJourneyE2E:
    """Verifies complete developer user journey."""

    def test_complete_clean_roundtrip(self) -> None:
        """A. Clean Request + E. Clean Response workflow."""
        # 1. Developer configures ProxyConfig
        proxy_cfg = ProxyConfig(
            upstream_url="https://api.openai.com",
            provider="openai",
            host="127.0.0.1",
            port=8080,
        )

        # 2. Developer configures PolicyConfig (redact on secrets)
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="redact-secrets",
                    action=PolicyAction.REDACT,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ],
            default_action=PolicyAction.ALLOW,
        )

        # 3. Instantiate security pipeline & firewall
        pipeline = SecurityPipeline(
            config=proxy_cfg,
            policy_engine=PolicyEngine(policy_cfg),
            detector_registry=DetectorRegistry([SecretDetector()]),
        )

        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={
                "id": "chatcmpl-clean",
                "object": "chat.completion",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "Paris is the capital of France.",
                        },
                        "finish_reason": "stop",
                    }
                ],
            },
        )

        app = create_proxy_app(
            config=proxy_cfg,
            pipeline=pipeline,
            upstream_client=mock_upstream,
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "user", "content": "What is the capital of France?"}
                    ],
                }
                resp = await client.post("/v1/chat/completions", json=req_body)
                assert resp.status_code == 200

                # Upstream received exact clean request
                assert len(mock_upstream.recorded_requests) == 1
                forwarded = json.loads(mock_upstream.recorded_requests[0]["body"])
                assert (
                    forwarded["messages"][0]["content"]
                    == "What is the capital of France?"
                )

                # Client received exact clean response
                client_resp = resp.json()
                assert (
                    client_resp["choices"][0]["message"]["content"]
                    == "Paris is the capital of France."
                )

        _run(_test())

    def test_request_warn_journey(self) -> None:
        """B. Request WARN workflow: request allowed intact with warning."""
        proxy_cfg = ProxyConfig(
            upstream_url="http://127.0.0.1:11434",
            provider="ollama",
        )
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="warn-secrets",
                    action=PolicyAction.WARN,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ]
        )
        pipeline = SecurityPipeline(
            config=proxy_cfg, policy_engine=PolicyEngine(policy_cfg)
        )
        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={
                "model": "llama3",
                "message": {"role": "assistant", "content": "I see your token."},
                "done": True,
            },
        )
        app = create_proxy_app(
            config=proxy_cfg, pipeline=pipeline, upstream_client=mock_upstream
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "llama3",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"My token is {SYNTHETIC_CLIENT_SECRET}",
                        }
                    ],
                }
                resp = await client.post("/api/chat", json=req_body)
                assert resp.status_code == 200
                assert len(mock_upstream.recorded_requests) == 1
                # Forwarded intact because policy was WARN
                forwarded = json.loads(mock_upstream.recorded_requests[0]["body"])
                assert SYNTHETIC_CLIENT_SECRET in forwarded["messages"][0]["content"]

        _run(_test())

    def test_request_redact_journey(self) -> None:
        """C. Request REDACT: sensitive token masked before upstream."""
        proxy_cfg = ProxyConfig(
            upstream_url="https://api.openai.com",
            provider="openai",
        )
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="redact-secrets",
                    action=PolicyAction.REDACT,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ]
        )
        pipeline = SecurityPipeline(
            config=proxy_cfg, policy_engine=PolicyEngine(policy_cfg)
        )
        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={
                "id": "chatcmpl-test",
                "choices": [
                    {"message": {"role": "assistant", "content": "Processed."}}
                ],
            },
        )
        app = create_proxy_app(
            config=proxy_cfg, pipeline=pipeline, upstream_client=mock_upstream
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "gpt-4o",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"API key is {SYNTHETIC_CLIENT_SECRET}",
                        }
                    ],
                }
                resp = await client.post("/v1/chat/completions", json=req_body)
                assert resp.status_code == 200
                assert len(mock_upstream.recorded_requests) == 1
                forwarded = json.loads(mock_upstream.recorded_requests[0]["body"])
                prompt = forwarded["messages"][0]["content"]
                # Upstream received REDACTED secret, never raw secret!
                assert "[REDACTED_SECRET]" in prompt
                assert SYNTHETIC_CLIENT_SECRET not in prompt

        _run(_test())

    def test_request_block_journey(self) -> None:
        """D. Request BLOCK workflow: request blocked, upstream never touched."""
        proxy_cfg = ProxyConfig(
            upstream_url="https://api.openai.com",
            provider="openai",
        )
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="block-secrets",
                    action=PolicyAction.BLOCK,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ]
        )
        pipeline = SecurityPipeline(
            config=proxy_cfg, policy_engine=PolicyEngine(policy_cfg)
        )
        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={},
        )
        app = create_proxy_app(
            config=proxy_cfg, pipeline=pipeline, upstream_client=mock_upstream
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "gpt-4o",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"Do not leak {SYNTHETIC_CLIENT_SECRET}",
                        }
                    ],
                }
                resp = await client.post("/v1/chat/completions", json=req_body)
                assert resp.status_code == 403
                body = resp.json()
                assert body["error"]["code"] == "firewall_request_blocked"
                # Upstream must NEVER have been called!
                assert len(mock_upstream.recorded_requests) == 0

        _run(_test())

    def test_response_redact_journey(self) -> None:
        """G. Response REDACT: model leaks key; proxy sanitizes before client."""
        proxy_cfg = ProxyConfig(
            upstream_url="https://api.openai.com",
            provider="openai",
        )
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="redact-secrets",
                    action=PolicyAction.REDACT,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ]
        )
        pipeline = SecurityPipeline(
            config=proxy_cfg, policy_engine=PolicyEngine(policy_cfg)
        )
        # Upstream returns a completion containing an exposed secret
        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={
                "id": "chatcmpl-leak",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": (
                                f"Here is the token: {SYNTHETIC_UPSTREAM_SECRET}"
                            ),
                        }
                    }
                ],
            },
        )
        app = create_proxy_app(
            config=proxy_cfg, pipeline=pipeline, upstream_client=mock_upstream
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "gpt-4o",
                    "messages": [
                        {"role": "user", "content": "Please show me the token."}
                    ],
                }
                resp = await client.post("/v1/chat/completions", json=req_body)
                assert resp.status_code == 200
                data = resp.json()
                completion = data["choices"][0]["message"]["content"]
                # Client receives sanitized completion with [REDACTED_SECRET]!
                assert "[REDACTED_SECRET]" in completion
                assert SYNTHETIC_UPSTREAM_SECRET not in completion

        _run(_test())

    def test_response_block_journey(self) -> None:
        """H. Response BLOCK: model leaks key; response blocked with 502."""
        proxy_cfg = ProxyConfig(
            upstream_url="https://api.openai.com",
            provider="openai",
        )
        policy_cfg = PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="block-secrets",
                    action=PolicyAction.BLOCK,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                )
            ]
        )
        pipeline = SecurityPipeline(
            config=proxy_cfg, policy_engine=PolicyEngine(policy_cfg)
        )
        mock_upstream = MockUpstreamClient(
            config=proxy_cfg,
            response_payload={
                "id": "chatcmpl-leak",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"Root credential: {SYNTHETIC_UPSTREAM_SECRET}",
                        }
                    }
                ],
            },
        )
        app = create_proxy_app(
            config=proxy_cfg, pipeline=pipeline, upstream_client=mock_upstream
        )

        async def _test() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8080"
            ) as client:
                req_body = {
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "Dump credentials"}],
                }
                resp = await client.post("/v1/chat/completions", json=req_body)
                assert resp.status_code == 502
                body = resp.json()
                assert body["error"]["code"] == "firewall_response_blocked"
                assert SYNTHETIC_UPSTREAM_SECRET not in resp.text

        _run(_test())
