"""
Health check endpoints.
"""

from fastapi import APIRouter
from datetime import datetime

from src.models import HealthCheckResponse

router = APIRouter()


@router.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint.

    Returns:
        Health status and timestamp
    """
    return HealthCheckResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
    )
