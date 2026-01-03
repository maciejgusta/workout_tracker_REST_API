def test_workouts_delete_success_user(client, create_workout, user_auth_header):
    res1 = create_workout(name="Delete Me", headers=user_auth_header)
    workout_id = res1.json()["id"]

    res = client.delete(f"/v1/workouts/{workout_id}", headers=user_auth_header)
    assert res.status_code == 204

    res2 = client.get(f"/v1/workouts/{workout_id}", headers=user_auth_header)
    assert res2.status_code == 404


def test_workouts_delete_admin_any_user(
    client, create_user, create_workout, admin_auth_header
):
    user_res = create_user(username="user_i", password="testtest")
    workout = create_workout(
        name="Admin Delete", user_id=user_res.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.delete(f"/v1/workouts/{workout_id}", headers=admin_auth_header)
    assert res.status_code == 204


def test_workouts_delete_forbidden_scope(
    client, create_user, create_workout, user_auth_header, admin_auth_header
):
    other_user = create_user(username="user_j", password="testtest")
    workout = create_workout(
        name="Other", user_id=other_user.json()["id"], headers=admin_auth_header
    )
    workout_id = workout.json()["id"]

    res = client.delete(f"/v1/workouts/{workout_id}", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workouts_delete_unauthorized(client):
    res = client.delete("/v1/workouts/1")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workouts_delete_not_found(client, user_auth_header):
    res = client.delete("/v1/workouts/9999", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"
