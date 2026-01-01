from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from app.schemas.auth import Token, UserCreate, UserOut
from app.services.auth import (
    authenticate_user,
    create_user,
    store_refresh_token,
    rotate_refresh_tokens,
    delete_refresh_token,
)
from app.core.config import Settings, get_settings
from app.core.security import create_access_token, create_refresh_token
from app.dependencies import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post(
    "/login",
    response_model=Token,
    summary="Login",
    description=(
        "Authenticates using form data and returns an access token. "
        "Also sets a `refresh_token` HTTP-only cookie scoped to `/v1/auth`."
    ),
    responses={
        200: {
            "description": "Authenticated",
            "headers": {
                "Set-Cookie": {
                    "schema": {"type": "string"},
                    "description": "Sets refresh_token cookie",
                },
            },
        },
        401: {"description": "Incorrect username or password"},
        422: {"description": "Validation error (form data)"},
    },
)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db)
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})
    store_refresh_token(db, user.id, refresh_token)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        path="/v1/auth",
        max_age=60 * 60 * 24 * int(settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, token_type="bearer")

@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=UserOut,
    summary="Register",
    description="Creates a new user account.",
    responses={
        201: {"description": "User created"},
        409: {"description": "Username already exists"},
        422: {"description": "Validation error (e.g., min_length)"},
    },
)
async def register(
    user: UserCreate,
    db: Session = Depends(get_db)
) -> UserOut:
    user = create_user(db, user.username, user.password)
    return user


@router.post(
    "/refresh",
    response_model=Token,
    summary="Refresh access token",
    description=(
        "Rotates the refresh token and returns a new access token. "
        "Requires a valid `refresh_token` cookie."
    ),
    responses={
        200: {
            "description": "Token refreshed",
            "headers": {
                "Set-Cookie": {
                    "schema": {"type": "string"},
                    "description": "Rotates refresh_token cookie",
                },
            },
        },
        401: {"description": "Missing or invalid refresh token"},
    },
)
def refresh(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db)
) -> Token:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    access_token, rotated_refresh_token = rotate_refresh_tokens(db, refresh_token)

    response.set_cookie(
        key="refresh_token",
        value=rotated_refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        path="/v1/auth",
        max_age=60 * 60 * 24 * int(settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, token_type="bearer")

@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout",
    description="Deletes the refresh token cookie and revokes the token if present.",
    responses={
        204: {
            "description": "Logged out",
            "headers": {
                "Set-Cookie": {
                    "schema": {"type": "string"},
                    "description": "Clears refresh_token cookie",
                },
            },
        },
    },
)
def logout(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db)
):
    refresh_token = request.cookies.get("refresh_token")    
    if refresh_token:
        delete_refresh_token(db, refresh_token)

    response.delete_cookie(
        key="refresh_token",
        path="/v1/auth",
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
    )
