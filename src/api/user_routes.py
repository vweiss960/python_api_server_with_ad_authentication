"""
User information endpoints.
"""

from fastapi import APIRouter, Request, HTTPException

from src.models import UserInfo, UserGroupsResponse
from src.decorators.auth_decorators import require_auth
from src.utils.logger import get_logger

logger = get_logger("routes.user")

router = APIRouter(prefix="/api/user", tags=["User"])


@router.get("/info", response_model=UserInfo)
@require_auth
async def get_user_info(request: Request):
    """
    Get authenticated user information.

    Returns:
        User details including groups

    Raises:
        HTTPException: If user not authenticated
    """
    user = request.state.user

    return UserInfo(
        username=user.get("sub"),
        dn=user.get("dn"),
        display_name=user.get("display_name"),
        email=user.get("email"),
        groups=user.get("groups", []),
    )


@router.get("/groups", response_model=UserGroupsResponse)
@require_auth
async def get_user_groups(request: Request):
    """
    Get authenticated user's group memberships.

    Returns:
        User's groups and group count

    Raises:
        HTTPException: If user not authenticated
    """
    user = request.state.user
    groups = user.get("groups", [])

    return UserGroupsResponse(
        username=user.get("sub"),
        groups=groups,
    )
