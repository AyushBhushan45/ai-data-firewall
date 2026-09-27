"""FastAPI HTTP ingress and reverse proxy server for AI Data Firewall.

Coordinates request ingestion, security pipeline inspection, upstream forwarding,
and sanitized response emission with strict local-first security defaults.
"""

import re
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from aifirewall.providers.errors import (
    UnsupportedPayloadError,
    UnsupportedStreamingError,
)
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    ERR_INVALID_REQUEST,
    ERR_METHOD_NOT_ALLOWED,
    ERR_PAYLOAD_TOO_LARGE,
    ERR_REQUEST_BLOCKED,
    ERR_RESPONSE_BLOCKED,
    ERR_UNSUPPORTED_PAYLOAD,
    ERR_UNSUPPORTED_STREAMING,
    ERR_UPSTREAM_TIMEOUT,
    ERR_UPSTREAM_UNAVAILABLE,
    BlockedRequestError,
    BlockedResponseError,
    PayloadTooLargeError,
    UpstreamError,
    UpstreamTimeoutError,
    create_safe_error_payload,
)
from aifirewall.proxy.pipeline import SecurityPipeline
from aifirewall.proxy.upstream import UpstreamClient

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def _generate_request_id(incoming_header: str | None) -> str:
    """Generate or sanitize a correlation request ID."""
    if incoming_header and SAFE_ID_PATTERN.match(incoming_header.strip()):
        return incoming_header.strip()
    return f"req_{uuid.uuid4().hex[:16]}"


def create_proxy_app(
    config: ProxyConfig,
    pipeline: SecurityPipeline | None = None,
    upstream_client: UpstreamClient | None = None,
) -> FastAPI:
    """Construct and configure the FastAPI application for the reverse proxy.

    Args:
        config: Validated ProxyConfig.
        pipeline: SecurityPipeline instance (or defaults to standard).
        upstream_client: UpstreamClient instance (or defaults to standard).

    Returns:
        Configured FastAPI application instance.
    """
    sec_pipeline = pipeline if pipeline is not None else SecurityPipeline(config=config)
    upstream = (
        upstream_client
        if upstream_client is not None
        else UpstreamClient(config=config)
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        await upstream.start()
        yield
        await upstream.close()

    app = FastAPI(
        title="AI Data Firewall Proxy",
        description="Local-first reverse proxy and security inspection gateway.",
        version="0.1.0",
        docs_url=None,  # Disable public Swagger docs for security
        redoc_url=None,  # Disable public ReDoc
        openapi_url=None,  # Disable OpenAPI spec exposure
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        """Local health endpoint; exposes no environment or credentials."""
        return {"status": "ok"}

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy_catch_all(request: Request, full_path: str) -> Response:
        """Inspect inbound request, forward upstream, inspect response, and return."""
        method = request.method.upper()

        # Enforce allowed HTTP methods
        if method not in config.allowed_http_methods:
            return JSONResponse(
                status_code=405,
                content=create_safe_error_payload(
                    ERR_METHOD_NOT_ALLOWED,
                    f"HTTP method {method} is not permitted by proxy configuration.",
                ),
            )

        request_id = _generate_request_id(
            request.headers.get("x-request-id")
            or request.headers.get("x-correlation-id")
        )

        # 1. Inbound Request Processing
        content_type = request.headers.get("content-type")
        try:
            raw_body = await request.body()
            sanitized_request_body, _ = sec_pipeline.process_request(
                raw_body=raw_body,
                content_type_header=content_type,
                request_id=request_id,
            )
        except PayloadTooLargeError as err:
            return JSONResponse(
                status_code=err.status_code,
                content=create_safe_error_payload(ERR_PAYLOAD_TOO_LARGE, str(err)),
            )
        except BlockedRequestError as err:
            return JSONResponse(
                status_code=err.status_code,
                content=create_safe_error_payload(ERR_REQUEST_BLOCKED, str(err)),
            )
        except UnsupportedStreamingError as err:
            return JSONResponse(
                status_code=400,
                content=create_safe_error_payload(ERR_UNSUPPORTED_STREAMING, str(err)),
            )
        except UnsupportedPayloadError as err:
            return JSONResponse(
                status_code=400,
                content=create_safe_error_payload(ERR_UNSUPPORTED_PAYLOAD, str(err)),
            )
        except Exception:
            return JSONResponse(
                status_code=400,
                content=create_safe_error_payload(
                    ERR_INVALID_REQUEST,
                    "Inbound request could not be processed safely.",
                ),
            )

        # 2. Forward to Fixed Upstream
        query_string = request.url.query
        headers_dict = dict(request.headers)

        try:
            upstream_resp = await upstream.forward(
                method=method,
                path=full_path,
                query_string=query_string,
                headers=headers_dict,
                body=sanitized_request_body,
            )
        except UpstreamTimeoutError as err:
            return JSONResponse(
                status_code=err.status_code,
                content=create_safe_error_payload(ERR_UPSTREAM_TIMEOUT, str(err)),
            )
        except UpstreamError as err:
            return JSONResponse(
                status_code=err.status_code,
                content=create_safe_error_payload(ERR_UPSTREAM_UNAVAILABLE, str(err)),
            )
        except PayloadTooLargeError as err:
            return JSONResponse(
                status_code=502,
                content=create_safe_error_payload(ERR_PAYLOAD_TOO_LARGE, str(err)),
            )

        # 3. Outbound Response Processing
        resp_content_type = upstream_resp.headers.get("content-type")
        try:
            sanitized_resp_body, _ = sec_pipeline.process_response(
                raw_body=upstream_resp.body,
                content_type_header=resp_content_type,
                request_id=request_id,
            )
        except PayloadTooLargeError as err:
            return JSONResponse(
                status_code=502,
                content=create_safe_error_payload(ERR_PAYLOAD_TOO_LARGE, str(err)),
            )
        except BlockedResponseError as err:
            return JSONResponse(
                status_code=err.status_code,
                content=create_safe_error_payload(ERR_RESPONSE_BLOCKED, str(err)),
            )
        except Exception:
            return JSONResponse(
                status_code=502,
                content=create_safe_error_payload(
                    ERR_UPSTREAM_UNAVAILABLE,
                    "Upstream response could not be processed safely.",
                ),
            )

        # 4. Return sanitized response with original upstream status code
        resp_headers = dict(upstream_resp.headers)
        resp_headers["content-length"] = str(len(sanitized_resp_body))

        return Response(
            content=sanitized_resp_body,
            status_code=upstream_resp.status_code,
            headers=resp_headers,
        )

    return app


class FirewallProxy:
    """Manages the reverse proxy lifecycle and Uvicorn server execution."""

    def __init__(
        self,
        config: ProxyConfig,
        pipeline: SecurityPipeline | None = None,
        upstream_client: UpstreamClient | None = None,
    ) -> None:
        """Initialize the FirewallProxy server with configuration and pipeline.

        Args:
            config: ProxyConfig defining local binding and upstream target.
            pipeline: Optional custom SecurityPipeline.
            upstream_client: Optional custom UpstreamClient.
        """
        self._config = config
        self._pipeline = (
            pipeline if pipeline is not None else SecurityPipeline(config=config)
        )
        self._upstream = (
            upstream_client
            if upstream_client is not None
            else UpstreamClient(config=config)
        )
        self._app = create_proxy_app(
            config=self._config,
            pipeline=self._pipeline,
            upstream_client=self._upstream,
        )

    @property
    def config(self) -> ProxyConfig:
        """Return the proxy configuration."""
        return self._config

    @property
    def pipeline(self) -> SecurityPipeline:
        """Return the security pipeline."""
        return self._pipeline

    @property
    def upstream(self) -> UpstreamClient:
        """Return the upstream client."""
        return self._upstream

    @property
    def app(self) -> FastAPI:
        """Return the ASGI FastAPI application."""
        return self._app

    def run(self, **kwargs: Any) -> None:
        """Start the reverse proxy using Uvicorn.

        Binds strictly to config.host (default 127.0.0.1) and config.port.
        """
        uvicorn.run(
            self._app,
            host=self._config.host,
            port=self._config.port,
            log_level="info",
            access_log=False,  # Suppress raw HTTP logging to guarantee zero leakage
            **kwargs,
        )
