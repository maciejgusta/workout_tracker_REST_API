from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.core import security
from app.models.user import User
from app.services import auth


def delete_user(db: Session, user: User) -> None:
    try:
        rows = (
            db.query(User).filter(User.id == user.id).delete(synchronize_session=False)
        )
        if rows != 1:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user",
        ) from exc


def change_password(db: Session, user: User, new_password: str) -> None:
    if security.verify_password(new_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords must differ"
        )

    try:
        rows = (
            db.query(User)
            .filter(User.id == user.id)
            .update(
                {"password_hash": security.hash_password(new_password)},
                synchronize_session=False,
            )
        )
        if rows != 1:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password",
        ) from exc

    auth.delete_refresh_tokens_for_user(db, user)
    db.commit()
