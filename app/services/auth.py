from fastapi import HTTPException, status
from datetime import datetime, timezone
from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.security import (
    verify_password,
    hash_password,
    decode_token,
    hash_refresh_token,
    create_access_token,
    create_refresh_token,
)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def create_user(db: Session, username: str, password: str):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return None
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def store_refresh_token(db: Session, user_id: int, token: str) -> RefreshToken:
    payload = decode_token(token, token_type="refresh")
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    token_hash = hash_refresh_token(token)
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(refresh_token)
    db.commit()
    db.refresh(refresh_token)
    return refresh_token

def validate_refresh_token(db: Session, token: str) -> RefreshToken:
    invalid_refresh_token_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    payload = decode_token(token, token_type="refresh")
    if not payload or "sub" not in payload:
        raise invalid_refresh_token_exception
    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise invalid_refresh_token_exception

    token_hash = hash_refresh_token(token)
    valid_token = db.query(RefreshToken).filter(RefreshToken.user_id == user_id, RefreshToken.token_hash == token_hash, RefreshToken.expires_at >= datetime.now(timezone.utc)).first()
    if not valid_token:
        raise invalid_refresh_token_exception
    
    return valid_token

def delete_refresh_token(db: Session, token: str) -> None:
    token_hash = hash_refresh_token(token)
    db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).delete()
    db.commit()

def rotate_refresh_tokens(db: Session, token: str) -> tuple[str, str]:
    invalid_refresh_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
    )
    payload = decode_token(token, token_type="refresh")
    if not payload or "sub" not in payload:
        raise invalid_refresh_token_exception
    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise invalid_refresh_token_exception

    old_hash = hash_refresh_token(token)
    new_refresh = create_refresh_token({"sub": str(user_id)})
    new_payload = decode_token(new_refresh, token_type="refresh")
    if not new_payload or "exp" not in new_payload:
        raise invalid_refresh_token_exception

    expires_at = datetime.fromtimestamp(new_payload["exp"], tz=timezone.utc)
    new_hash = hash_refresh_token(new_refresh)

    try:
        result = db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.token_hash == old_hash,
                RefreshToken.expires_at >= datetime.now(timezone.utc),
            )
            .values(token_hash=new_hash, expires_at=expires_at)
            .returning(RefreshToken.user_id)
        )
        if result.scalar_one_or_none() is None:
            raise invalid_refresh_token_exception
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate refresh token",
        ) from exc

    access = create_access_token({"sub": str(user_id)})
    return access, new_refresh
