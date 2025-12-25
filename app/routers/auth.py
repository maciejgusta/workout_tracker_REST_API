from fastapi import Depends, HTTPException, status, Response, Request
from fastapi import APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from app.schemas.auth import Token, UserCreate, UserOut
from app.models.user import User
from app.services.auth import authenticate_user, create_user, store_refresh_token, rotate_refresh_tokens, delete_refresh_token
from app.core.config import Settings, get_settings
from app.core.security import create_access_token, create_refresh_token
from app.dependencies import get_db, get_current_user
from sqlalchemy.orm import Session
from typing import Annotated

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login", response_model=Token)
async def login(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
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

@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
async def register(
    user: UserCreate,
    db: Session = Depends(get_db)
) -> UserOut:
    user = create_user(db, user.username, user.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )
    return user

@router.get("/me", status_code=status.HTTP_200_OK, response_model=UserOut)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserOut:
    return current_user

@router.post("/refresh", response_model=Token)
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

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
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
