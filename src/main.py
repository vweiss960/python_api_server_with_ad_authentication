"""
FastAPI application entry point.

Main application configuration and startup/shutdown handlers.
"""

import sys
import argparse
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import uvicorn

from src.config import ConfigLoader
from src.utils.logger import setup_logging, get_logger
from src.utils.errors import APIException, ConfigurationError
from src.security.auth import LDAPAuthenticator
from src.security.jwt_handler import JWTHandler
from src.security.authorization import AuthorizationManager
from src.middleware.auth_middleware import AuthenticationMiddleware
from src.middleware.logging_middleware import LoggingMiddleware
from src.api import health_routes, auth_routes, user_routes, data_routes, admin_routes, webhook_routes
from src.middleware.basic_auth_middleware import BasicAuthMiddleware
from src.security.credential_cache import CredentialCache

logger = None


def setup_app(config_path: str) -> FastAPI:
    """
    Setup FastAPI application with configuration and dependencies.

    Args:
        config_path: Path to configuration file

    Returns:
        Configured FastAPI application

    Raises:
        ConfigurationError: If configuration is invalid
    """
    global logger

    # Load configuration
    try:
        config_loader = ConfigLoader(config_path)
        config = config_loader.get()

        # Validate configuration
        validation_errors = config_loader.validate()
        if validation_errors:
            for error in validation_errors:
                print(f"Configuration error: {error}", file=sys.stderr)
            raise ConfigurationError("Invalid configuration")

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}", file=sys.stderr)
        sys.exit(1)
    except ConfigurationError as e:
        print(f"Configuration error: {e.message}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    log_level = "DEBUG"
    logger = setup_logging(level=log_level, json_format=True)
    logger.info(f"Application starting with config: {config_path}")

    # Initialize security components
    try:
        authenticator = LDAPAuthenticator(config.ad)
        jwt_handler = JWTHandler(config.jwt)
        auth_manager = AuthorizationManager(config.authorization)

        # Validate authorization rules
        rule_errors = auth_manager.validate_rules()
        if rule_errors:
            for error in rule_errors:
                logger.error(f"Authorization rule error: {error}")
            raise ConfigurationError("Invalid authorization rules")

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e.message}")
        raise

    logger.info("Security components initialized successfully")

    # Initialize credential cache for Basic Auth
    basic_auth_cache = None
    if config.authorization.basic_auth_cache_enabled:
        basic_auth_cache = CredentialCache(
            ttl_seconds=config.authorization.basic_auth_cache_ttl_seconds,
            max_size=config.authorization.basic_auth_cache_max_size,
        )
        logger.info(
            f"Credential cache initialized (TTL: {config.authorization.basic_auth_cache_ttl_seconds}s, Max: {config.authorization.basic_auth_cache_max_size})"
        )

    # Create FastAPI application
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        logger.info("Application startup")
        # Store cache in app state for access from routes
        app.state.basic_auth_cache = basic_auth_cache
        try:
            authenticator.test_connection()
            logger.info("AD connection test passed")
        except Exception as e:
            logger.warning(f"AD connection test failed (non-fatal): {str(e)}")
        yield
        # Shutdown
        logger.info("Application shutdown")
        authenticator.close()

    app = FastAPI(
        title="API Server with AD Authentication",
        description="REST API with Active Directory authentication and group-based authorization",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Add middleware (ORDER MATTERS! They execute in reverse order of addition)
    app.add_middleware(LoggingMiddleware)
    # Basic Auth middleware added AFTER JWT so it executes BEFORE JWT
    if basic_auth_cache:
        app.add_middleware(BasicAuthMiddleware, authenticator=authenticator, cache=basic_auth_cache)
    app.add_middleware(AuthenticationMiddleware, jwt_handler=jwt_handler)

    # Setup dependency injection for route handlers
    def get_authenticator():
        return authenticator

    def get_jwt_handler():
        return jwt_handler

    def get_auth_manager():
        return auth_manager

    app.dependency_overrides[LDAPAuthenticator] = get_authenticator
    app.dependency_overrides[JWTHandler] = get_jwt_handler
    app.dependency_overrides[AuthorizationManager] = get_auth_manager

    # Include routers
    app.include_router(health_routes.router)
    app.include_router(auth_routes.router)
    app.include_router(user_routes.router)
    app.include_router(data_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(webhook_routes.router)

    # Exception handlers
    @app.exception_handler(APIException)
    async def api_exception_handler(request: Request, exc: APIException):
        logger.error(f"API Exception: {exc.error} - {exc.message}")
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_response(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning(f"Validation error: {exc}")
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "Request validation failed",
                "details": exc.errors(),
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "http_error",
                "message": exc.detail,
            },
        )

    return app


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="API Server with Active Directory Authentication"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to configuration file (YAML or JSON)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Port to bind to (default: 8443)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        help="Path to SSL key file (overrides config)",
    )
    parser.add_argument(
        "--ssl-certfile",
        help="Path to SSL certificate file (overrides config)",
    )

    args = parser.parse_args()

    # Setup application
    app = setup_app(args.config)

    # Get config for SSL settings
    config_loader = ConfigLoader(args.config)
    config = config_loader.get()

    # Determine SSL settings
    ssl_keyfile = args.ssl_keyfile or (config.server.key_file if config.server.tls_enabled else None)
    ssl_certfile = args.ssl_certfile or (config.server.cert_file if config.server.tls_enabled else None)

    # Warn if TLS disabled
    if not config.server.tls_enabled:
        if logger:
            logger.warning("⚠️  TLS is disabled! This is only suitable for development.")
        else:
            print("⚠️  WARNING: TLS is disabled! This is only suitable for development.", file=sys.stderr)

    # Run application
    host = args.host or config.server.host
    port = args.port or config.server.port

    if logger:
        logger.info(f"Starting server on {host}:{port}")

    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        log_config=None,  # Disable uvicorn logging, use our logger
    )


if __name__ == "__main__":
    main()
