def test_workouts_create_success_user(create_workout, user_auth_header):
    res = create_workout(name="Leg Day", headers=user_auth_header)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Leg Day"
    assert set(data.keys()) == {"id", "name"}


def test_workouts_create_success_admin_for_user(
    create_user, create_workout, admin_auth_header
):
    user_res = create_user(username="user_a", password="testtest")
    user_id = user_res.json()["id"]

    res = create_workout(
        name="Admin Workout", user_id=user_id, headers=admin_auth_header
    )
    assert res.status_code == 201
    data = res.json()
    assert data["user_id"] == user_id
    assert "created_at" in data
    assert "updated_at" in data


def test_workouts_create_forbidden_non_admin(create_workout, user_auth_header):
    res = create_workout(name="Bad", user_id=999, headers=user_auth_header)
    assert res.status_code == 403
    assert res.json().get("detail") == "Setting user id is for admin only"


def test_workouts_create_user_not_found(create_workout, admin_auth_header):
    res = create_workout(name="Missing User", user_id=99999, headers=admin_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "User not found"


def test_workouts_create_unauthorized(client):
    res = client.post("/v1/workouts/", json={"name": "No Auth"})
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workouts_create_validation_error(
    client, user_auth_header, assert_missing_field
):
    res = client.post("/v1/workouts/", json={}, headers=user_auth_header)
    assert_missing_field(res, "name")
