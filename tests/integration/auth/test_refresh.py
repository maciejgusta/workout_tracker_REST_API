from datetime import timedelta

import pytest
from fastapi import HTTPException
from freezegun import freeze_time

from app.core import security
from app.schemas.auth import Token
from app.services import auth

def test_refresh_success(client, db_session, create_user, login_user):
    with freeze_time() as frozen_time:
        res1 = create_user()
        assert res1.status_code == 201
        assert "id" in res1.json()
        user_id = res1.json().get("id")

        res2 = login_user()
        assert res2.status_code == 200
        assert res2.cookies.get("refresh_token") is not None
        initial_refresh_token = res2.cookies.get("refresh_token")
        frozen_time.tick(delta=timedelta(seconds=3)) # change time to get different refresh token

        res3 = client.post("/v1/auth/refresh")
        assert res3.status_code == 200
        assert res3.cookies.get("refresh_token") is not None
        set_cookies = res3.headers.get_list("set-cookie")
        refresh_header = next(c for c in set_cookies if c.startswith("refresh_token=")).lower()
        assert "httponly" in refresh_header
        assert "path=/v1/auth/refresh" in refresh_header
        assert "samesite=lax" in refresh_header
        new_refresh_token = res3.cookies.get("refresh_token")
        assert new_refresh_token != initial_refresh_token

        token_obj: Token = Token.model_validate(res3.json())
        assert token_obj.token_type == "bearer"
        access_token = token_obj.access_token
        payload = security.decode_token(access_token, "access")
        assert payload is not None
        assert "sub" in payload.keys()
        assert int(payload.get("sub")) == user_id
        assert payload["typ"] == "access"

        with pytest.raises(HTTPException) as exc:
            auth.validate_refresh_token(db_session, initial_refresh_token)
        assert exc.value.status_code == 401
        assert exc.value.detail == "Invalid refresh token"

def test_refresh_missing_token(client):
    res = client.post("/v1/auth/refresh")
    assert res.status_code == 401
    assert res.json().get("detail") == "Missing refresh token"

def test_refresh_garbage_token(client):
    client.cookies.set("refresh_token", "garbage_string")
    res = client.post("/v1/auth/refresh")
    assert res.status_code == 401
    assert res.json().get("detail") == "Invalid refresh token"

def test_refresh_wrong_token_type(client, create_user, login_user):
    res1 = create_user()
    assert res1.status_code == 201
    res2 = login_user()
    assert res2.status_code == 200
    token_obj: Token = Token.model_validate(res2.json())
    client.cookies.set("refresh_token", token_obj.access_token)
    res3 = client.post("/v1/auth/refresh")
    assert res3.status_code == 401
    assert res3.json().get("detail") == "Invalid refresh token"

def test_refresh_expired_token(client, db_session, create_user, settings):
    with freeze_time() as frozen_time:
        res1 = create_user()
        assert res1.status_code == 201
        assert "id" in res1.json()
        user_id = int(res1.json().get("id"))
        refresh_token = security.create_refresh_token({"sub": str(user_id)})
        assert refresh_token is not None
        stored_refresh_token = auth.store_refresh_token(db_session, user_id, refresh_token)
        assert stored_refresh_token is not None
        client.cookies.set("refresh_token", refresh_token)
        days_tick = settings.REFRESH_TOKEN_EXPIRE_DAYS + 1
        frozen_time.tick(delta=timedelta(days=days_tick)) # get time from settings
        res2 = client.post("/v1/auth/refresh")
        assert res2.status_code == 401
        assert res2.json().get("detail") == "Invalid refresh token"
    
def test_refresh_token_not_in_db(client, db_session, create_user, login_user):
    res1 = create_user()
    assert res1.status_code == 201
    res2 = login_user()
    assert res2.status_code == 200
    assert res2.cookies.get("refresh_token") is not None
    refresh_token = res2.cookies.get("refresh_token")
    auth.delete_refresh_token(db_session, refresh_token)
    res3 = client.post("/v1/auth/refresh")
    assert res3.status_code == 401
    assert res3.json().get("detail") == "Invalid refresh token"
