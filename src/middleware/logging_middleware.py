"""
Request logging middleware.
"""

import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from src.utils.logger import get_logger

logger = get_logger("middleware.logging")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests with response details."""

    async def dispatch(self, request: Request, call_next):
        """
        Log HTTP request and response.

        Args:
            request: HTTP request
            call_next: Next middleware in chain

        Returns:
            Response
        """
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Extract user info if available
        username = "anonymous"
        if hasattr(request.state, "user"):
            username = request.state.user.get("sub", "unknown")

        # Record start time
        start_time = time.time()

        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "user": username,
                "method": request.method,
                "path": request.url.path,
            }
        )

        # Call next middleware/handler
        response = await call_next(request)

        # Calculate response time
        response_time_ms = (time.time() - start_time) * 1000

        # Log response
        logger.info(
            f"Response: {response.status_code} in {response_time_ms:.2f}ms",
            extra={
                "request_id": request_id,
                "user": username,
                "status_code": response.status_code,
                "response_time": response_time_ms,
            }
        )

        # Add request ID to response header
        response.headers["X-Request-ID"] = request_id

        return response
