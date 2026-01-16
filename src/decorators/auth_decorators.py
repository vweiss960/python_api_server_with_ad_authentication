"""
Decorators for authentication and authorization.
"""

from functools import wraps
from typing import Callable, List, Optional
from fastapi import Request, HTTPException

from src.utils.logger import get_logger
from src.utils.errors import AuthorizationError

logger = get_logger("decorators")


def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication on an endpoint.

    Checks that the request has a valid JWT token in the Authorization header.
    The token is validated and attached to the request for use by the route handler.

    Usage:
        @app.get("/api/protected")
        @require_auth
        async def protected_route(request: Request):
            # User is authenticated
            user_info = request.state.user
    """
    @wraps(func)
    async def wrapper(*args, request: Request = None, **kwargs):
        # The actual token validation happens in middleware
        # This decorator just checks that middleware set user info
        if not hasattr(request.state, "user"):
            raise HTTPException(status_code=401, detail="Authentication required")

        return await func(*args, request=request, **kwargs)

    return wrapper


def require_groups(groups: List[str]):
    """
    Decorator to require user membership in specific groups.

    Requires user to be in ALL of the specified groups (AND logic).

    Usage:
        @app.get("/api/admin/settings")
        @require_groups(["API-Admins"])
        async def get_settings(request: Request):
            # User must be in API-Admins group
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            if not hasattr(request.state, "user"):
                raise HTTPException(status_code=401, detail="Authentication required")

            user_groups = request.state.user.get("groups", [])

            # Check if user is in all required groups
            for group in groups:
                if group not in user_groups:
                    logger.warning(
                        f"User {request.state.user.get('sub')} lacks required group: {group}"
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient permissions. Required groups: {groups}",
                    )

            return await func(*args, request=request, **kwargs)

        return wrapper
    return decorator


def require_any_group(groups: List[str]):
    """
    Decorator to require user membership in at least one of the specified groups.

    Requires user to be in ANY of the specified groups (OR logic).

    Usage:
        @app.post("/api/data/write")
        @require_any_group(["Data-Writers", "Data-Admins"])
        async def write_data(request: Request):
            # User must be in either Data-Writers or Data-Admins group
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            if not hasattr(request.state, "user"):
                raise HTTPException(status_code=401, detail="Authentication required")

            user_groups = request.state.user.get("groups", [])

            # Check if user is in at least one required group
            if not any(group in user_groups for group in groups):
                logger.warning(
                    f"User {request.state.user.get('sub')} not in any required group"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required groups: {groups}",
                )

            return await func(*args, request=request, **kwargs)

        return wrapper
    return decorator


def require_not_in_group(groups: List[str]):
    """
    Decorator to require user NOT be in specific groups.

    Rejects request if user is in ANY of the specified groups.

    Usage:
        @app.get("/api/data/read")
        @require_not_in_group(["Restricted-Users"])
        async def read_data(request: Request):
            # User must NOT be in Restricted-Users group
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, request: Request = None, **kwargs):
            if not hasattr(request.state, "user"):
                raise HTTPException(status_code=401, detail="Authentication required")

            user_groups = request.state.user.get("groups", [])

            # Check if user is in any excluded groups
            if any(group in user_groups for group in groups):
                logger.warning(
                    f"User {request.state.user.get('sub')} is in excluded group"
                )
                raise HTTPException(
                    status_code=403,
                    detail="Access denied",
                )

            return await func(*args, request=request, **kwargs)

        return wrapper
    return decorator
