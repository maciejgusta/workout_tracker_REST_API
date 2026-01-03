from app.models.user import User


def test_users_delete_me_success(
    client, create_user, login_user, db_session, auth_header
):
    res1 = create_user()
    assert res1.status_code == 201
    username = res1.json().get("username")

    res2 = login_user()
    assert res2.status_code == 200

    res3 = client.delete("/v1/users/me", headers=auth_header(res2))
    assert res3.status_code == 204
    set_cookies = res3.headers.get_list("set-cookie")
    refresh_header = next(
        c for c in set_cookies if c.startswith("refresh_token=")
    ).lower()
    assert "path=/v1/auth" in refresh_header
    assert "samesite=strict" in refresh_header

    deleted_user = db_session.query(User).filter(User.username == username).first()
    assert deleted_user is None


def test_users_delete_me_unauthorized(client):
    res = client.delete("/v1/users/me")
    assert res.status_code == 401
