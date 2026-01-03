def test_workout_exercises_list_unauthorized(client):
    res = client.get("/v1/workouts/1/exercises")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workout_exercises_list_not_found(client, user_auth_header):
    res = client.get("/v1/workouts/9999/exercises", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workout_exercises_list_invalid_id(client, user_auth_header):
    res = client.get("/v1/workouts/abc/exercises", headers=user_auth_header)
    assert res.status_code == 422


def test_workout_exercises_list_user_scope(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Leg Day", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    ex1 = create_exercise_db(name="Bench Press A")
    ex2 = create_exercise_db(name="Squat A")

    res1 = create_workout_exercise(workout_id, ex1.id, headers=user_auth_header)
    res2 = create_workout_exercise(workout_id, ex2.id, headers=user_auth_header)
    assert res1.status_code == 201
    assert res2.status_code == 201

    res = client.get(f"/v1/workouts/{workout_id}/exercises", headers=user_auth_header)
    assert res.status_code == 200
    items = res.json()
    assert [item["exercise_id"] for item in items] == [ex1.id, ex2.id]
    assert all("created_at" not in item for item in items)
    assert all("updated_at" not in item for item in items)


def test_workout_exercises_list_admin_sees_metadata(
    client,
    create_user,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    admin_auth_header,
):
    user_res = create_user(username="user_we_a", password="testtest")
    workout_res = create_workout(
        name="Admin Workout", user_id=user_res.json()["id"], headers=admin_auth_header
    )
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Deadlift A")

    res1 = create_workout_exercise(workout_id, exercise.id, headers=admin_auth_header)
    assert res1.status_code == 201

    res = client.get(f"/v1/workouts/{workout_id}/exercises", headers=admin_auth_header)
    assert res.status_code == 200
    item = res.json()[0]
    assert item["exercise_id"] == exercise.id
    assert "created_at" in item
    assert "updated_at" in item


def test_workout_exercises_list_forbidden_scope(
    client,
    create_user,
    create_workout,
    user_auth_header,
    admin_auth_header,
):
    other_user = create_user(username="user_we_b", password="testtest")
    workout_res = create_workout(
        name="Other", user_id=other_user.json()["id"], headers=admin_auth_header
    )
    workout_id = workout_res.json()["id"]

    res = client.get(f"/v1/workouts/{workout_id}/exercises", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"
