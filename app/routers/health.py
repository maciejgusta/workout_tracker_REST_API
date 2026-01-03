from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.dependencies import get_db


router = APIRouter(prefix="", tags=["health"])


@router.get(
    "/health",
    summary="Health check",
    description="Basic liveness probe.",
    responses={200: {"description": "Service is healthy"}},
)
async def health():
    return {"status": "ok"}


@router.get(
    "/ready",
    summary="Readiness check",
    description="Checks database connectivity.",
    responses={
        200: {"description": "Service is ready"},
        503: {"description": "Database unavailable"},
    },
)
def ready(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    return {"status": "ok"}
