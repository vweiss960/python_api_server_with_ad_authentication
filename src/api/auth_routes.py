"""
Authentication endpoints.
"""

from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime

from src.models import LoginRequest, LoginResponse, UserInfo
from src.security.auth import LDAPAuthenticator
from src.security.jwt_handler import JWTHandler
from src.utils.logger import get_logger
from src.utils.errors import (
    InvalidCredentialsError,
    ADConnectionError,
    APIException,
)

logger = get_logger("routes.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, authenticator: LDAPAuthenticator = Depends(), jwt_handler: JWTHandler = Depends()):
    """
    Login endpoint.

    Authenticates user against Active Directory and returns JWT token.

    Args:
        request: Login request with username and password
        authenticator: LDAP authenticator
        jwt_handler: JWT token handler

    Returns:
        LoginResponse with token and user info

    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Authenticate against AD
        user_info = authenticator.authenticate(request.username, request.password)

        # Generate JWT token
        token = jwt_handler.generate_token(user_info, use_simple_names=True)

        logger.info(f"User {user_info.username} successfully logged in")

        return LoginResponse(
            token=token,
            user=UserInfo(
                username=user_info.username,
                dn=user_info.dn,
                display_name=user_info.display_name,
                email=user_info.email,
                groups=user_info.groups,
            ),
            expires_in=jwt_handler.get_token_expiration(),
        )

    except InvalidCredentialsError as e:
        logger.warning(f"Login failed for {request.username}: {e.message}")
        raise HTTPException(status_code=401, detail=e.message)

    except ADConnectionError as e:
        logger.error(f"AD connection error during login: {e.message}")
        raise HTTPException(status_code=500, detail="Authentication service unavailable")

    except APIException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")
