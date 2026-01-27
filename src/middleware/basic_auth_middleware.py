"""
Basic Authentication middleware for webhook endpoints.

Handles HTTP Basic Authentication for /webhooks/* paths.
Authenticates credentials against LDAP and caches successful authentications.
Sets request.state.user in the same format as JWT authentication.
"""

import base64
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.security.auth import LDAPAuthenticator
from src.security.credential_cache import CredentialCache
from src.utils.logger import get_logger
from src.utils.errors import InvalidCredentialsError, ADConnectionError

logger = get_logger("middleware.basic_auth")


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware for Basic Authentication on webhook endpoints.

    Handles only /webhooks/* paths. For all other paths, passes through unchanged.
    Extracts credentials from Authorization header, authenticates against LDAP,
    caches successful authentications, and populates request.state.user.
    """

    def __init__(self, app, authenticator: LDAPAuthenticator, cache: CredentialCache = None):
        """
        Initialize Basic Auth middleware.

        Args:
            app: FastAPI application
            authenticator: LDAPAuthenticator instance for AD authentication
            cache: CredentialCache instance for caching (optional)
        """
        super().__init__(app)
        self.authenticator = authenticator
        self.cache = cache

    def _is_webhook_path(self, path: str) -> bool:
        """
        Check if path is a webhook endpoint.

        Args:
            path: Request path

        Returns:
            True if path starts with /webhooks/, False otherwise
        """
        return path.startswith("/webhooks/")

    def _extract_credentials(self, request: Request) -> tuple[str, str]:
        """
        Extract username and password from Basic Auth header.

        Parses "Authorization: Basic <base64>" format where base64 decodes
        to "username:password".

        Args:
            request: FastAPI request

        Returns:
            Tuple of (username, password)

        Raises:
            InvalidCredentialsError: If header is missing or malformed
        """
        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            raise InvalidCredentialsError("Authorization header required")

        # Parse "Basic <base64>" format
        parts = auth_header.split(" ")
        if len(parts) != 2 or parts[0].lower() != "basic":
            raise InvalidCredentialsError("Invalid Authorization header format. Expected: Basic <base64>")

        try:
            decoded = base64.b64decode(parts[1]).decode("utf-8")
        except Exception:
            raise InvalidCredentialsError("Invalid base64 encoding in Authorization header")

        if ":" not in decoded:
            raise InvalidCredentialsError("Invalid credentials format. Expected: username:password")

        username, password = decoded.split(":", 1)
        return username, password

    def _extract_simple_group_names(self, group_dns: list) -> list:
        """
        Extract simple group names from full DNs.

        Converts "CN=admin_users,OU=Groups,DC=example,DC=com" to "admin_users".

        Args:
            group_dns: List of group distinguished names

        Returns:
            List of simple group names
        """
        if not group_dns:
            return []

        group_names = []
        for dn in group_dns:
            try:
                cn_part = dn.split(",")[0]
                if cn_part.startswith("CN="):
                    group_name = cn_part[3:]
                    group_names.append(group_name)
                else:
                    group_names.append(dn)
            except:
                group_names.append(dn)

        return group_names

    def _create_user_payload(self, user_info) -> dict:
        """
        Convert UserInfo to request.state.user dict format (matching JWT).

        Critical: Must match the exact structure that JWT middleware uses.
        Existing decorators (@require_auth, @require_groups) expect this format.

        Args:
            user_info: UserInfo dataclass from LDAP authentication

        Returns:
            Dictionary with keys: sub, dn, groups, display_name, email
        """
        # Extract simple group names from full DNs
        simple_group_names = self._extract_simple_group_names(user_info.groups)

        return {
            "sub": user_info.username,
            "dn": user_info.dn,
            "groups": simple_group_names,
            "display_name": user_info.display_name,
            "email": user_info.email,
        }

    async def dispatch(self, request: Request, call_next):
        """
        Process request with Basic Auth for webhooks.

        For non-webhook paths, passes through unchanged.
        For webhook paths:
        1. Extracts credentials from Authorization header
        2. Tries to get cached user info
        3. If not cached, authenticates via LDAP
        4. Caches successful authentication
        5. Sets request.state.user
        6. Calls next middleware

        Args:
            request: FastAPI request
            call_next: Next middleware/handler

        Returns:
            Response from next middleware/handler or error response
        """
        # Pass through immediately if not a webhook path
        if not self._is_webhook_path(request.url.path):
            return await call_next(request)

        logger.debug(f"Processing webhook request: {request.method} {request.url.path}")

        try:
            # Extract credentials from header
            username, password = self._extract_credentials(request)
            logger.debug(f"Extracted credentials for user: {username}")

            user_info = None

            # Try cache first
            if self.cache:
                user_info = self.cache.get(username, password)
                if user_info:
                    logger.info(f"Using cached authentication for user {username}")

            # If not in cache, authenticate via LDAP
            if not user_info:
                logger.debug(f"Authenticating user {username} with LDAP")
                user_info = self.authenticator.authenticate(username, password)
                logger.info(f"Successfully authenticated user {username} via LDAP")

                # Cache the successful authentication
                if self.cache:
                    self.cache.put(username, password, user_info)
                    logger.debug(f"Cached authentication for user {username}")

            # Set request.state.user in JWT-compatible format
            request.state.user = self._create_user_payload(user_info)
            logger.debug(f"Set request.state.user for {username}")

            # Call next middleware
            return await call_next(request)

        except InvalidCredentialsError as e:
            logger.warning(f"Invalid credentials for webhook: {e.message}")
            return JSONResponse(
                status_code=401,
                content={"detail": e.message},
                headers={"WWW-Authenticate": 'Basic realm="Webhooks"'},
            )

        except ADConnectionError as e:
            logger.error(f"AD connection error during webhook auth: {e.message}")
            return JSONResponse(
                status_code=503,
                content={"detail": "Authentication service unavailable"},
            )

        except Exception as e:
            logger.error(f"Unexpected error during webhook authentication: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication failed"},
                headers={"WWW-Authenticate": 'Basic realm="Webhooks"'},
            )
