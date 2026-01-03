import os
from app.db.database import SessionLocal
from app.models.user import User, UserRole
from app.core.security import hash_password


def main():
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if not username or not password:
        raise SystemExit("ADMIN_USERNAME and ADMIN_PASSWORD must be set")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            return
        admin = User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
