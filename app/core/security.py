from datetime import timedelta, datetime, timezone
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from pwdlib import PasswordHash
import hmac
import hashlib
from app.core.config import get_settings

settings = get_settings()

password_hash = PasswordHash.recommended()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def hash_refresh_token(token: str) -> str:
    secret = settings.JWT_SECRET.get_secret_value().encode("utf-8")
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_refresh_token(token: str, token_hash: str) -> bool:
    expected = hash_refresh_token(token)
    return hmac.compare_digest(expected, token_hash)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "typ": "access",
        }
    )
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=int(settings.REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "typ": "refresh",
        }
    )
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_token(token: str, token_type: str | None = None) -> dict | None:
    try:
        decode_kwargs = {
            "key": settings.JWT_SECRET.get_secret_value(),
            "algorithms": [settings.JWT_ALGORITHM],
            "options": {
                "require": ["exp", "sub", "iss", "aud", "typ"],
            },
            "audience": settings.JWT_AUDIENCE,
            "issuer": settings.JWT_ISSUER
        }
        payload = jwt.decode(token, **decode_kwargs)
        if token_type and payload.get("typ") != token_type:
            return None
        return payload
    except ExpiredSignatureError:
        return None
    except InvalidTokenError:
        return None
