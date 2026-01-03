def test_workouts_update_success_user(client, create_workout, user_auth_header):
    res1 = create_workout(name="Old Name", headers=user_auth_header)
    workout_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}",
        json={"name": "New Name"},
        headers=user_auth_header,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == workout_id
    assert data["name"] == "New Name"
    assert set(data.keys()) == {"id", "name"}


def test_workouts_update_admin_any_user(
    client, create_user, create_workout, admin_auth_header
):
    user_res = create_user(username="user_g", password="testtest")
    workout = create_workout(
        name="Admin Update", user_id=user_res.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}",
        json={"name": "Updated"},
        headers=admin_auth_header,
    )
    assert res.status_code == 200
    assert res.json()["name"] == "Updated"
    assert res.json()["user_id"] == user_res.json()["id"]


def test_workouts_update_no_fields(client, create_workout, user_auth_header):
    res1 = create_workout(name="No Fields", headers=user_auth_header)
    workout_id = res1.json()["id"]

    res = client.patch(f"/v1/workouts/{workout_id}", json={}, headers=user_auth_header)
    assert res.status_code == 400
    assert res.json().get("detail") == "No fields provided"


def test_workouts_update_forbidden_scope(
    client, create_user, create_workout, user_auth_header, admin_auth_header
):
    other_user = create_user(username="user_h", password="testtest")
    workout = create_workout(
        name="Other", user_id=other_user.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}",
        json={"name": "Nope"},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workouts_update_unauthorized(client):
    res = client.patch("/v1/workouts/1", json={"name": "No Auth"})
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workouts_update_not_found(client, user_auth_header):
    res = client.patch(
        "/v1/workouts/9999", json={"name": "Missing"}, headers=user_auth_header
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workouts_update_validation_error(client, create_workout, user_auth_header):
    res1 = create_workout(name="Bad Update", headers=user_auth_header)
    workout_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}",
        json={"name": ""},
        headers=user_auth_header,
    )
    assert res.status_code == 422
