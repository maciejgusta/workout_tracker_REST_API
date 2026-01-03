def test_users_me_success(client, create_user, login_user, auth_header):
    res1 = create_user()
    assert res1.status_code == 201

    res2 = login_user()
    assert res2.status_code == 200

    res3 = client.get("/v1/users/me", headers=auth_header(res2))
    assert res3.status_code == 200
    assert set(res3.json().keys()) == {"id", "username", "created_at"}


def test_users_me_unauthorized(client):
    res = client.get("/v1/users/me")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"
