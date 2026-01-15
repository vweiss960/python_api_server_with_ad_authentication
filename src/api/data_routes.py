"""
Data access endpoints.
"""

from fastapi import APIRouter, Request, HTTPException

from src.decorators.auth_decorators import require_auth, require_any_group
from src.utils.logger import get_logger

logger = get_logger("routes.data")

router = APIRouter(prefix="/api/data", tags=["Data"])


@router.get("/read")
@require_auth
@require_any_group(["Data-Readers", "Data-Writers"])
async def read_data(request: Request):
    """
    Read data endpoint.

    Requires user to be in Data-Readers OR Data-Writers group.

    Returns:
        Sample data

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    logger.info(f"User {user.get('sub')} reading data")

    return {
        "message": "Data read successful",
        "user": user.get("sub"),
        "data": [
            {"id": 1, "value": "Sample data 1"},
            {"id": 2, "value": "Sample data 2"},
        ],
    }


@router.post("/write")
@require_auth
@require_any_group(["Data-Writers"])
async def write_data(request: Request):
    """
    Write data endpoint.

    Requires user to be in Data-Writers group.

    Returns:
        Confirmation of write operation

    Raises:
        HTTPException: If user not authenticated or lacks required group
    """
    user = request.state.user
    logger.info(f"User {user.get('sub')} writing data")

    return {
        "message": "Data written successfully",
        "user": user.get("sub"),
        "timestamp": "2024-01-01T00:00:00Z",
    }
