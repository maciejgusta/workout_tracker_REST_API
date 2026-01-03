def test_sets_list_unauthorized(client):
    res = client.get("/v1/workouts/1/exercises/1/sets")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_sets_list_workout_not_found(client, user_auth_header):
    res = client.get("/v1/workouts/9999/exercises/1/sets", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_sets_list_invalid_id(client, user_auth_header):
    res = client.get("/v1/workouts/abc/exercises/1/sets", headers=user_auth_header)
    assert res.status_code == 422


def test_sets_list_user_scope(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Sets List", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move A")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    res2 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=6
    )
    assert res1.status_code == 201
    assert res2.status_code == 201

    res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=user_auth_header,
    )
    assert res.status_code == 200
    items = res.json()
    assert [item["set_index"] for item in items] == [1, 2]
    assert all("created_at" not in item for item in items)
    assert all("updated_at" not in item for item in items)


def test_sets_list_admin_sees_metadata(
    client,
    create_user,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    admin_auth_header,
):
    user_res = create_user(username="user_sets_admin", password="testtest")
    workout_res = create_workout(
        name="Admin Sets",
        user_id=user_res.json()["id"],
        headers=admin_auth_header,
    )
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move B")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=admin_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=admin_auth_header, repetitions=8
    )
    assert res1.status_code == 201

    res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=admin_auth_header,
    )
    assert res.status_code == 200
    item = res.json()[0]
    assert item["workout_exercise_id"] == workout_exercise_id
    assert "created_at" in item
    assert "updated_at" in item


def test_sets_list_forbidden_scope(
    client,
    create_user,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
    admin_auth_header,
):
    other_user = create_user(username="user_sets_other", password="testtest")
    workout_res = create_workout(
        name="Other Sets",
        user_id=other_user.json()["id"],
        headers=admin_auth_header,
    )
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move C")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=admin_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]
    res1 = create_set(
        workout_id, workout_exercise_id, headers=admin_auth_header, repetitions=7
    )
    assert res1.status_code == 201

    res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"
