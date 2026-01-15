"""
Pydantic models for API requests and responses.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class LoginRequest(BaseModel):
    """Login request model."""
    username: str = Field(..., description="Username (sAMAccountName, Domain\\Username, or UPN)")
    password: str = Field(..., description="User password")


class LoginResponse(BaseModel):
    """Login response model."""
    token: str = Field(..., description="JWT authentication token")
    user: "UserInfo"
    expires_in: int = Field(..., description="Token expiration time in hours")


class UserInfo(BaseModel):
    """User information model."""
    username: str
    dn: Optional[str] = None
    display_name: Optional[str] = None
    email: Optional[str] = None
    groups: List[str] = Field(default_factory=list)


class UserGroupsResponse(BaseModel):
    """User groups response model."""
    username: str
    groups: List[str] = Field(default_factory=list)
    group_count: int = 0

    def __init__(self, **data):
        super().__init__(**data)
        self.group_count = len(self.groups)


class HealthCheckResponse(BaseModel):
    """Health check response model."""
    status: str = "healthy"
    timestamp: datetime
    version: str = "1.0.0"


class AuthorizationRule(BaseModel):
    """Authorization rule model."""
    path: str
    groups: List[str]
    require: str = "any"
    exclude_groups: Optional[List[str]] = None


class AuthorizationRulesResponse(BaseModel):
    """Authorization rules response model."""
    rules: List[AuthorizationRule]
    rule_count: int = 0

    def __init__(self, **data):
        super().__init__(**data)
        self.rule_count = len(self.rules)


class AccessCheckRequest(BaseModel):
    """Request to check access to a path."""
    path: str = Field(..., description="Path to check access for")


class AccessCheckResponse(BaseModel):
    """Response for access check."""
    path: str
    authorized: bool
    required_groups: Optional[List[str]] = None
    message: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None


class TokenValidationResponse(BaseModel):
    """Token validation response."""
    valid: bool
    username: Optional[str] = None
    groups: Optional[List[str]] = None
    expires_at: Optional[datetime] = None
    message: Optional[str] = None
