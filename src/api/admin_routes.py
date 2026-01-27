"""
Administrative endpoints.
"""

from fastapi import APIRouter, Request, HTTPException, Depends

from src.models import AuthorizationRulesResponse, AuthorizationRule, AccessCheckRequest, AccessCheckResponse
from src.decorators.auth_decorators import require_auth, require_any_group
from src.security.authorization import AuthorizationManager
from src.utils.logger import get_logger

logger = get_logger("routes.admin")

router = APIRouter(prefix="/api/admin", tags=["Administration"])


#############################################################################
### HELLO WORLD GET #####
#############################################################################

@router.get("/hello_world")
@require_auth
@require_any_group(["admin_users"])
async def say_hello(request: Request):
    user = request.state.user
    logger.info(f"Admin {user.get('sub')} accessed hello_world")

    return {
        "message": "hello world!",
    }

#############################################################################
### HELLO WORLD POST #####
#############################################################################

##### CRATE THE DATA MODEL FOR THE DATA TO BE RECEIVED #####
from pydantic import BaseModel
class Name_Object(BaseModel):
    """name payload."""
    name: str

@router.post("/hello_world")
@require_auth
@require_any_group(["admin_users"])
async def say_hello_to_user(request: Request, data: Name_Object):
    user = request.state.user
    logger.info(f"Admin {user.get('sub')} manipulated hello_world name")

    return {
        "message": f"hello {data.name}!",
    }


#############################################################################


@router.get("/users")
@require_auth
@require_any_group(["admin_users"])
async def list_users(request: Request):
    """
    List users endpoint (admin only).

    Requires user to be in API-Admins group.

    Returns:
        Sample list of users

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    logger.info(f"Admin {user.get('sub')} accessed user list")

    return {
        "message": "User list retrieved",
        "users": [
            {"id": 1, "username": "user1", "email": "user1@example.com"},
            {"id": 2, "username": "user2", "email": "user2@example.com"},
        ],
    }


@router.delete("/users/{user_id}")
@require_auth
@require_any_group(["admin_users"])
async def delete_user(user_id: str, request: Request):
    """
    Delete user endpoint (admin only).

    Requires user to be in API-Admins group.

    Args:
        user_id: ID of user to delete

    Returns:
        Confirmation of deletion

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    admin = request.state.user
    logger.info(f"Admin {admin.get('sub')} deleted user {user_id}")

    return {
        "message": f"User {user_id} deleted successfully",
        "deleted_by": admin.get("sub"),
    }


@router.get("/settings")
@require_auth
@require_any_group(["admin_users"])
async def get_settings(request: Request):
    """
    Get application settings (admin only).

    Requires user to be in API-Admins group.

    Returns:
        Application settings

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    logger.info(f"Admin {user.get('sub')} accessed settings")

    return {
        "message": "Settings retrieved",
        "settings": {
            "log_level": "INFO",
            "session_timeout": 3600,
        },
    }


@router.get("/rules", response_model=AuthorizationRulesResponse)
@require_auth
@require_any_group(["admin_users"])
async def get_authorization_rules(request: Request):
    """
    Get configured authorization rules (admin only).

    Requires user to be in API-Admins group.

    Returns:
        List of authorization rules

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    logger.info(f"Admin {user.get('sub')} accessed authorization rules")

    # Get auth manager from app dependency overrides
    auth_manager = request.app.dependency_overrides[AuthorizationManager]()

    rules = auth_manager.get_all_rules()
    auth_rules = [
        AuthorizationRule(
            path=rule.path,
            groups=rule.groups,
            require=rule.require,
            exclude_groups=rule.exclude_groups,
        )
        for rule in rules
    ]

    return AuthorizationRulesResponse(rules=auth_rules)


@router.post("/check-access", response_model=AccessCheckResponse)
@require_auth
@require_any_group(["admin_users"])
async def check_access(request: Request, check_request: AccessCheckRequest):
    """
    Check if current user has access to a specific path (admin only).

    Useful for UI to determine which endpoints to show.

    Args:
        check_request: Request with path to check

    Returns:
        Authorization check result

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    user_groups = user.get("groups", [])

    # Get auth manager from app dependency overrides
    auth_manager = request.app.dependency_overrides[AuthorizationManager]()

    authorized, required_groups, message = auth_manager.check_authorization(
        check_request.path,
        user_groups,
    )

    logger.info(f"Access check for {check_request.path}: {'allowed' if authorized else 'denied'}")

    return AccessCheckResponse(
        path=check_request.path,
        authorized=authorized,
        required_groups=required_groups,
        message=message,
    )
