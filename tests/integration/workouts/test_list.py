def test_workouts_list_unauthorized(client):
    res = client.get("/v1/workouts/")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workouts_list_user_scope(
    client, create_user, create_workout, user_auth_header, admin_auth_header
):
    res1 = create_workout(name="Mine", headers=user_auth_header)
    assert res1.status_code == 201

    other_user = create_user(username="user_b", password="testtest")
    other_id = other_user.json()["id"]
    res2 = create_workout(name="Other", user_id=other_id, headers=admin_auth_header)
    assert res2.status_code == 201

    res = client.get("/v1/workouts/", headers=user_auth_header)
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 1
    assert items[0]["name"] == "Mine"
    assert set(items[0].keys()) == {"id", "name"}


def test_workouts_list_admin_sees_all(
    client, create_user, create_workout, admin_auth_header
):
    user_a = create_user(username="user_c", password="testtest")
    user_b = create_user(username="user_d", password="testtest")
    res1 = create_workout(
        name="W1", user_id=user_a.json()["id"], headers=admin_auth_header
    )
    res2 = create_workout(
        name="W2", user_id=user_b.json()["id"], headers=admin_auth_header
    )
    assert res1.status_code == 201
    assert res2.status_code == 201

    res = client.get("/v1/workouts/", headers=admin_auth_header)
    assert res.status_code == 200
    names = {item["name"] for item in res.json()}
    assert names == {"W1", "W2"}
