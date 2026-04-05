"""
middleware.py — Request-scoped trace ID injection.

Every inbound request gets a trace_id (from X-Request-ID header if present,
otherwise generated fresh). This ID is:
  1. Set in the logging context (appears on every log line for this request)
  2. Returned in the X-Request-ID response header (for client-side correlation)

In a full OpenTelemetry setup, this would instead extract the W3C traceparent
header and propagate it through to OPA and Postgres spans.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from logging_config import set_trace_id, get_logger

log = get_logger(__name__)


class TraceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Honour upstream trace ID (e.g. from load balancer) or generate one
        trace_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        set_trace_id(trace_id)

        log.debug(
            "request.start",
            extra={
                "method": request.method,
                "path":   request.url.path,
            },
        )

        response = await call_next(request)
        response.headers["X-Request-ID"] = trace_id

        log.debug(
            "request.end",
            extra={
                "method": request.method,
                "path":   request.url.path,
                "status": response.status_code,
            },
        )
        return response
