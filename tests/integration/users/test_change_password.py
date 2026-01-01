import pytest
from fastapi import HTTPException

from app.schemas.auth import Token
from app.services import auth


def test_users_change_password_success(client, create_user, login_user, db_session, auth_header):
    old_password = "testtest"
    new_password = "newpass12"

    res1 = create_user(password=old_password)
    assert res1.status_code == 201

    res2 = login_user(password=old_password)
    assert res2.status_code == 200
    refresh_token = res2.cookies.get("refresh_token")
    assert refresh_token is not None
    auth.validate_refresh_token(db_session, refresh_token)

    res3 = client.post(
        "/v1/users/me/change-password",
        headers=auth_header(res2),
        json={"current_password": old_password, "new_password": new_password},
    )
    assert res3.status_code == 204
    set_cookies = res3.headers.get_list("set-cookie")
    refresh_header = next(c for c in set_cookies if c.startswith("refresh_token=")).lower()
    assert "path=/v1/auth" in refresh_header
    assert "samesite=strict" in refresh_header

    with pytest.raises(HTTPException) as exc:
        auth.validate_refresh_token(db_session, refresh_token)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid refresh token"

    res4 = login_user(password=old_password)
    assert res4.status_code == 401

    res5 = login_user(password=new_password)
    assert res5.status_code == 200
    token_obj = Token.model_validate(res5.json())
    assert token_obj.access_token is not None


def test_users_change_password_invalid_current(client, create_user, login_user, auth_header):
    res1 = create_user(password="testpass1")
    assert res1.status_code == 201
    res2 = login_user(password="testpass1")
    assert res2.status_code == 200

    res3 = client.post(
        "/v1/users/me/change-password",
        headers=auth_header(res2),
        json={"current_password": "wrongpass", "new_password": "newpass12"},
    )
    assert res3.status_code == 401
    assert res3.json().get("detail") == "Current password is invalid"


def test_users_change_password_too_short(client, create_user, login_user, auth_header):
    password = "testtest"
    res1 = create_user(password=password)
    assert res1.status_code == 201
    res2 = login_user(password=password)
    assert res2.status_code == 200

    res3 = client.post(
        "/v1/users/me/change-password",
        headers=auth_header(res2),
        json={"current_password": password, "new_password": "short"},
    )
    assert res3.status_code == 422


def test_users_change_password_unauthorized(client):
    res = client.post(
        "/v1/users/me/change-password",
        json={"current_password": "testtest", "new_password": "newpass12"},
    )
    assert res.status_code == 401
