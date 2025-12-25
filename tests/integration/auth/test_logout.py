from app.services import auth
from fastapi import HTTPException
import pytest

def test_logout_success(client, db_session, create_user, login_user):
    res1 = create_user()
    assert res1.status_code == 201

    res2 = login_user()
    assert res2.status_code == 200

    assert res2.cookies.get("refresh_token") is not None
    refresh_token = res2.cookies.get("refresh_token")

    res3 = client.post("/v1/auth/logout")
    assert res3.status_code == 204
    assert res3.cookies.get("refresh_token") is None
    set_cookies = res3.headers.get_list("set-cookie")
    refresh_header = next(c for c in set_cookies if c.startswith("refresh_token=")).lower()
    assert "path=/v1/auth" in refresh_header
    assert "httponly" in refresh_header
    assert "samesite=strict" in refresh_header
    assert "max-age=0" in refresh_header or "expires=" in refresh_header
    
    with pytest.raises(HTTPException) as exc:
        auth.validate_refresh_token(db_session, refresh_token)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid refresh token"

def test_logout_no_refresh_token(client):
    res = client.post("/v1/auth/logout")
    assert res.status_code == 204

def test_logout_garbage_token(client):
    client.cookies.set("refresh_token", "garbage_string")
    res = client.post("/v1/auth/logout")
    assert res.status_code == 204

def test_logout_token_revoked(client, db_session, create_user, login_user):
    res1 = create_user()
    assert res1.status_code == 201
    res2 = login_user()
    assert res2.status_code == 200
    assert res2.cookies.get("refresh_token") is not None
    refresh_token = res2.cookies.get("refresh_token")
    auth.delete_refresh_token(db_session, refresh_token)
    res3 = client.post("/v1/auth/logout")
    assert res3.status_code == 204
