def test_workouts_get_success_user(client, create_workout, user_auth_header):
    res1 = create_workout(name="My Workout", headers=user_auth_header)
    workout_id = res1.json()["id"]

    res = client.get(f"/v1/workouts/{workout_id}", headers=user_auth_header)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == workout_id
    assert data["name"] == "My Workout"
    assert set(data.keys()) == {"id", "name"}


def test_workouts_get_admin_any_user(
    client, create_user, create_workout, admin_auth_header
):
    user_res = create_user(username="user_e", password="testtest")
    workout = create_workout(
        name="Other Workout", user_id=user_res.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.get(f"/v1/workouts/{workout_id}", headers=admin_auth_header)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == workout_id
    assert data["user_id"] == user_res.json()["id"]


def test_workouts_get_forbidden_scope(
    client, create_user, create_workout, user_auth_header, admin_auth_header
):
    other_user = create_user(username="user_f", password="testtest")
    workout = create_workout(
        name="Other", user_id=other_user.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.get(f"/v1/workouts/{workout_id}", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workouts_get_unauthorized(client):
    res = client.get("/v1/workouts/1")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workouts_get_not_found(client, user_auth_header):
    res = client.get("/v1/workouts/9999", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workouts_get_invalid_id(client, user_auth_header):
    res = client.get("/v1/workouts/abc", headers=user_auth_header)
    assert res.status_code == 422
