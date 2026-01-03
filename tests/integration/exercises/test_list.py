def test_exercises_list_unauthorized(client):
    res = client.get("/v1/exercises/")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_exercises_list_success_user(client, create_exercise_db, user_auth_header):
    create_exercise_db(name="Alpha", is_active=True)
    create_exercise_db(name="Hidden", is_active=False)

    res = client.get("/v1/exercises/", headers=user_auth_header)
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["name"] == "Alpha"
    assert "is_active" not in item
    assert "created_at" not in item
    assert "updated_at" not in item


def test_exercises_list_success_admin(client, create_exercise_db, admin_auth_header):
    create_exercise_db(name="Alpha", is_active=True)
    create_exercise_db(name="Hidden", is_active=False)

    res = client.get("/v1/exercises/", headers=admin_auth_header)
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    names = {item["name"] for item in body["items"]}
    assert names == {"Alpha", "Hidden"}
    assert all("is_active" in item for item in body["items"])


def test_exercises_list_filtering(client, create_exercise_db, user_auth_header):
    create_exercise_db(name="Bench Press")
    create_exercise_db(name="Incline Bench")
    create_exercise_db(name="Squat")

    res = client.get(
        "/v1/exercises/", headers=user_auth_header, params={"name": "bench"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    names = {item["name"] for item in body["items"]}
    assert names == {"Bench Press", "Incline Bench"}


def test_exercises_list_pagination(client, create_exercise_db, user_auth_header):
    create_exercise_db(name="Alpha")
    create_exercise_db(name="Bravo")
    create_exercise_db(name="Charlie")

    res = client.get(
        "/v1/exercises/", headers=user_auth_header, params={"limit": 2, "offset": 0}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert [item["name"] for item in body["items"]] == ["Alpha", "Bravo"]

    res2 = client.get(
        "/v1/exercises/", headers=user_auth_header, params={"limit": 2, "offset": 2}
    )
    assert res2.status_code == 200
    body2 = res2.json()
    assert body2["total"] == 3
    assert len(body2["items"]) == 1
    assert body2["items"][0]["name"] == "Charlie"
