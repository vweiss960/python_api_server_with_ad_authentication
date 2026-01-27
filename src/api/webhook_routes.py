"""
Webhook endpoints with Basic Authentication.

These endpoints use HTTP Basic Authentication instead of JWT tokens.
All endpoints require authentication via @require_auth decorator.
Some endpoints have additional group restrictions via @require_any_group decorator.
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.decorators.auth_decorators import require_auth, require_any_group
from src.utils.logger import get_logger

logger = get_logger("routes.webhooks")

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


class WebhookDataRequest(BaseModel):
    """Webhook data payload."""
    event_type: str
    data: dict


class WebhookEventRequest(BaseModel):
    """Webhook event payload."""
    event: str
    payload: dict


@router.post("/data")
@require_auth
@require_any_group(["admin_users"])
async def webhook_data(request: Request, payload: WebhookDataRequest):
    """
    Data webhook endpoint.

    Requires Basic Auth with user in admin_users group.

    Args:
        request: FastAPI request object (contains authenticated user info in request.state.user)
        payload: Webhook data payload

    Returns:
        JSON response with status and received_by username
    """
    user = request.state.user
    logger.info(f"Webhook data received from {user.get('sub')}: {payload.event_type}")

    return {
        "status": "success",
        "message": "Data webhook processed",
        "event_type": payload.event_type,
        "received_by": user.get("sub"),
    }


@router.post("/events")
@require_auth
async def webhook_events(request: Request, payload: WebhookEventRequest):
    """
    Generic event webhook.

    Requires Basic Auth with any valid user (no group restriction).

    Args:
        request: FastAPI request object (contains authenticated user info in request.state.user)
        payload: Webhook event payload

    Returns:
        JSON response with status and received_by username
    """
    user = request.state.user
    logger.info(f"Webhook event received from {user.get('sub')}: {payload.event}")

    return {
        "status": "success",
        "message": "Event webhook processed",
        "event": payload.event,
        "received_by": user.get("sub"),
    }


@router.get("/cache/stats")
@require_auth
@require_any_group(["admin_users"])
async def get_cache_stats(request: Request):
    """
    Get credential cache statistics (admin only).

    Requires Basic Auth with admin_users group membership.

    Args:
        request: FastAPI request object

    Returns:
        JSON response with cache statistics
    """
    # Get cache from app.state
    cache = getattr(request.app.state, "basic_auth_cache", None)

    if not cache:
        return {"cache_stats": {"error": "Cache not initialized"}}

    stats = cache.get_stats()

    user = request.state.user
    logger.info(f"Cache stats requested by {user.get('sub')}")

    return {"cache_stats": stats}
