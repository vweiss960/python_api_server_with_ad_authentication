"""
JWT token generation and validation.
"""

import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from src.config import JWTConfig
from src.utils.logger import get_logger
from src.utils.errors import JWTValidationError
from src.security.auth import UserInfo

logger = get_logger("jwt")


class JWTHandler:
    """Handles JWT token generation and validation."""

    def __init__(self, config: JWTConfig):
        """
        Initialize JWT handler.

        Args:
            config: JWT configuration
        """
        self.config = config

    def _extract_group_names(self, group_dns: List[str], use_simple_names: bool = True) -> List[str]:
        """
        Extract group names from DNs.

        Args:
            group_dns: List of group distinguished names
            use_simple_names: If True, extract just the CN part

        Returns:
            List of group names
        """
        if not use_simple_names:
            return group_dns

        group_names = []
        for dn in group_dns:
            # Extract CN from DN
            # DN format: CN=group_name,OU=Groups,DC=example,DC=com
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

    def generate_token(self, user_info: UserInfo, use_simple_names: bool = True) -> str:
        """
        Generate JWT token for authenticated user.

        Args:
            user_info: User information from authentication
            use_simple_names: If True, use simple group names instead of DNs

        Returns:
            JWT token string

        Raises:
            JWTValidationError: If token generation fails
        """
        try:
            now = datetime.now(timezone.utc)
            expiration = now + timedelta(hours=self.config.expiration_hours)

            payload = {
                "sub": user_info.username,
                "dn": user_info.dn,
                "iat": now,
                "exp": expiration,
            }

            # Add optional fields
            if user_info.display_name:
                payload["display_name"] = user_info.display_name
            if user_info.email:
                payload["email"] = user_info.email

            # Add groups to token if configured
            if self.config.include_groups:
                groups = self._extract_group_names(user_info.groups, use_simple_names)
                payload["groups"] = groups
                logger.debug(f"Added {len(groups)} groups to token for user {user_info.username}")

            token = jwt.encode(
                payload,
                self.config.secret,
                algorithm=self.config.algorithm,
            )

            logger.info(f"Generated JWT token for user {user_info.username}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate JWT token: {str(e)}")
            raise JWTValidationError("Failed to generate authentication token")

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token and extract claims.

        Args:
            token: JWT token string

        Returns:
            Token claims (payload)

        Raises:
            JWTValidationError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                self.config.secret,
                algorithms=[self.config.algorithm],
            )
            logger.debug(f"Successfully validated token for user {payload.get('sub')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token validation failed: token expired")
            raise JWTValidationError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT token validation failed: {str(e)}")
            raise JWTValidationError("Invalid token")
        except Exception as e:
            logger.error(f"Unexpected error validating JWT: {str(e)}")
            raise JWTValidationError("Token validation failed")

    def get_token_expiration(self) -> int:
        """Get token expiration time in hours."""
        return self.config.expiration_hours

    def get_groups_from_token(self, token_payload: Dict[str, Any]) -> List[str]:
        """
        Extract groups from token payload.

        Args:
            token_payload: Decoded JWT token payload

        Returns:
            List of group names/DNs
        """
        return token_payload.get("groups", [])

    def get_username_from_token(self, token_payload: Dict[str, Any]) -> str:
        """
        Extract username from token payload.

        Args:
            token_payload: Decoded JWT token payload

        Returns:
            Username
        """
        return token_payload.get("sub", "")

    def get_dn_from_token(self, token_payload: Dict[str, Any]) -> str:
        """
        Extract distinguished name from token payload.

        Args:
            token_payload: Decoded JWT token payload

        Returns:
            User's DN
        """
        return token_payload.get("dn", "")
