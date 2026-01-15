"""
Custom exceptions and error response models.
"""

from dataclasses import dataclass
from typing import Optional, Any, Dict


@dataclass
class ErrorResponse:
    """Standard error response format."""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response."""
        result = {
            "error": self.error,
            "message": self.message,
        }
        if self.details:
            result["details"] = self.details
        return result


class APIException(Exception):
    """Base class for API exceptions."""

    def __init__(self, error: str, message: str, status_code: int = 500, details: Optional[Dict] = None):
        self.error = error
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)

    def to_response(self) -> Dict[str, Any]:
        """Convert to error response."""
        return ErrorResponse(
            error=self.error,
            message=self.message,
            details=self.details,
        ).to_dict()


class AuthenticationError(APIException):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed", details: Optional[Dict] = None):
        super().__init__(
            error="authentication_error",
            message=message,
            status_code=401,
            details=details,
        )


class InvalidCredentialsError(APIException):
    """Raised when credentials are invalid."""

    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(
            error="invalid_credentials",
            message=message,
            status_code=401,
        )


class MissingAuthenticationError(APIException):
    """Raised when authentication is required but not provided."""

    def __init__(self, message: str = "Authentication required"):
        super().__init__(
            error="missing_authentication",
            message=message,
            status_code=401,
        )


class AuthorizationError(APIException):
    """Raised when user lacks required permissions."""

    def __init__(self, message: str = "Insufficient permissions", required_groups: Optional[list] = None):
        details = None
        if required_groups:
            details = {"required_groups": required_groups}

        super().__init__(
            error="authorization_error",
            message=message,
            status_code=403,
            details=details,
        )


class ConfigurationError(APIException):
    """Raised when configuration is invalid."""

    def __init__(self, message: str):
        super().__init__(
            error="configuration_error",
            message=message,
            status_code=500,
        )


class ADConnectionError(APIException):
    """Raised when AD connection fails."""

    def __init__(self, message: str = "Failed to connect to Active Directory"):
        super().__init__(
            error="ad_connection_error",
            message=message,
            status_code=500,
        )


class JWTValidationError(APIException):
    """Raised when JWT validation fails."""

    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(
            error="jwt_validation_error",
            message=message,
            status_code=401,
        )
