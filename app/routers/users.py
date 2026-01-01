from fastapi import APIRouter, Depends, status, Response, HTTPException
from app.models.user import User
from app.schemas.auth import UserOut
from app.dependencies import get_current_user, get_db
from sqlalchemy.orm import Session
from app.core.config import get_settings, Settings
from app.schemas.users import ChangePassword
from app.services import auth, users

router = APIRouter(prefix="/users", tags=["users"])


def _clear_refresh_cookie(response: Response, settings: Settings) -> Response:
    response.status_code = status.HTTP_204_NO_CONTENT
    response.delete_cookie(
        key="refresh_token",
        path="/v1/auth",
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
    )
    return response


@router.get(
    "/me",
    status_code=status.HTTP_200_OK,
    response_model=UserOut,
    summary="Get current user",
    description="Returns the authenticated user's profile.",
    responses={
        401: {"description": "Not authenticated"},
    },
)
def me(
    current_user: User = Depends(get_current_user)
) -> UserOut:
    return current_user

@router.delete(
    "/me",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete current user",
    description="Deletes the authenticated user and clears the refresh cookie.",
    responses={
        204: {
            "description": "Deleted",
            "headers": {
                "Set-Cookie": {
                    "schema": {"type": "string"},
                    "description": "Clears refresh_token cookie",
                },
            },
        },
        401: {"description": "Not authenticated"},
    },
)
def delete_me(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings)
):
    users.delete_user(db, current_user)
    return _clear_refresh_cookie(response, settings)

@router.post(
    "/me/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change password",
    description=(
        "Validates current password, updates to new password, "
        "revokes refresh tokens, and clears cookie."
    ),
    responses={
        204: {
            "description": "Password changed",
            "headers": {
                "Set-Cookie": {
                    "schema": {"type": "string"},
                    "description": "Clears refresh_token cookie",
                },
            },
        },
        400: {"description": "New password must differ"},
        401: {"description": "Not authenticated or current password invalid"},
        422: {"description": "Validation error (e.g., min_length)"},
    },
)
def change_password(
    response: Response,
    change_password: ChangePassword,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings)
):
    authenticated_user = auth.authenticate_user(db, current_user.username, change_password.current_password)
    if (authenticated_user is None or authenticated_user.id != current_user.id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is invalid")
    
    users.change_password(db, current_user, change_password.new_password)
    return _clear_refresh_cookie(response, settings)
    
