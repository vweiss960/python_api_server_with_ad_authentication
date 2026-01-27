"""
Authentication middleware for validating JWT tokens.
"""

import re
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.security.jwt_handler import JWTHandler
from src.utils.logger import get_logger
from src.utils.errors import JWTValidationError, MissingAuthenticationError

logger = get_logger("middleware.auth")

# Paths that don't require authentication
PUBLIC_PATHS = {
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/login",
}


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to validate JWT tokens on protected routes."""

    def __init__(self, app, jwt_handler: JWTHandler):
        super().__init__(app)
        self.jwt_handler = jwt_handler

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public (doesn't require auth)."""
        # Check exact matches first
        if path in PUBLIC_PATHS:
            return True
        # Check webhook paths (handled by BasicAuthMiddleware)
        if path.startswith("/webhooks/"):
            return True
        return False

    def _extract_token(self, request: Request) -> str:
        """
        Extract JWT token from Authorization header.

        Supports "Bearer <token>" format.

        Returns:
            Token string

        Raises:
            MissingAuthenticationError: If token not found
        """
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            raise MissingAuthenticationError("Authorization header required")

        # Parse "Bearer <token>" format
        match = re.match(r"Bearer\s+(.+)", auth_header)
        if not match:
            raise MissingAuthenticationError("Invalid Authorization header format. Expected: Bearer <token>")

        return match.group(1)

    async def dispatch(self, request: Request, call_next):
        """
        Process request and validate authentication if required.

        Args:
            request: HTTP request
            call_next: Next middleware in chain

        Returns:
            Response
        """
        # Check if path requires authentication
        if self._is_public_path(request.url.path):
            logger.debug(f"Public path: {request.url.path}")
            return await call_next(request)

        # Extract and validate token
        try:
            token = self._extract_token(request)
            payload = self.jwt_handler.validate_token(token)

            # Attach user info to request state
            request.state.user = payload
            logger.debug(f"User authenticated: {payload.get('sub')}")

        except (MissingAuthenticationError, JWTValidationError) as e:
            logger.warning(f"Authentication failed for {request.url.path}: {e.message}")
            return JSONResponse(
                status_code=e.status_code,
                content=e.to_response(),
            )

        # Call next middleware/handler
        response = await call_next(request)
        return response
