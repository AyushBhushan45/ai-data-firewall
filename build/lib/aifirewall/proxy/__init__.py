"""Local HTTP reverse proxy and security pipeline for AI Data Firewall."""

from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    BlockedRequestError,
    BlockedResponseError,
    PayloadTooLargeError,
    ProxyError,
    UpstreamError,
    UpstreamTimeoutError,
    create_safe_error_payload,
)
from aifirewall.proxy.extraction import PayloadExtractor
from aifirewall.proxy.models import ExtractedItem, ExtractionResult, PipelineResult
from aifirewall.proxy.pipeline import DetectorRegistry, SecurityPipeline
from aifirewall.proxy.server import FirewallProxy, create_proxy_app
from aifirewall.proxy.upstream import UpstreamClient, UpstreamResponse

__all__ = [
    "ProxyConfig",
    "FirewallProxy",
    "SecurityPipeline",
    "DetectorRegistry",
    "PayloadExtractor",
    "UpstreamClient",
    "UpstreamResponse",
    "create_proxy_app",
    "ExtractedItem",
    "ExtractionResult",
    "PipelineResult",
    "ProxyError",
    "UpstreamError",
    "UpstreamTimeoutError",
    "PayloadTooLargeError",
    "BlockedRequestError",
    "BlockedResponseError",
    "create_safe_error_payload",
]
