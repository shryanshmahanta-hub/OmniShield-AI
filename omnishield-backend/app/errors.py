"""Error handlers and custom exceptions for OmniShield AI."""

from typing import Any, Dict, Optional
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


class OmniShieldError(Exception):
    """Base exception for OmniShield domain errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class VendorNotFoundError(OmniShieldError):
    """Raised when an invoice references an unknown vendor."""
    pass


class StorageError(OmniShieldError):
    """Raised when incident persistence fails."""
    pass


class ExternalServiceError(OmniShieldError):
    """Raised when an external ML inference server fails."""
    pass


def setup_exception_handlers(app: FastAPI) -> None:
    """Register custom exception handlers on FastAPI instance."""

    @app.exception_handler(OmniShieldError)
    async def omnishield_error_handler(request: Request, exc: OmniShieldError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": exc.__class__.__name__,
                "message": exc.message,
                "details": exc.details,
            },
        )

    @app.exception_handler(StorageError)
    async def storage_error_handler(request: Request, exc: StorageError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "StorageError",
                "message": exc.message,
            },
        )
