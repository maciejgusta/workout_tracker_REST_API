from sqlalchemy.exc import IntegrityError


def test_sets_update_success_reorder(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set Update", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move J")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    create_set(workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5)
    res2 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=6
    )
    set_id = res2.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        json={"set_index": 1},
        headers=user_auth_header,
    )
    assert res.status_code == 200
    assert res.json()["set_index"] == 1

    list_res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=user_auth_header,
    )
    items = list_res.json()
    assert [item["repetitions"] for item in items] == [6, 5]
    assert [item["set_index"] for item in items] == [1, 2]


def test_sets_update_success_change_values(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set Update Values", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move K")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    set_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        json={"weight": 100.5, "repetitions": 8, "rpe": 7},
        headers=user_auth_header,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["weight"] == 100.5
    assert data["repetitions"] == 8
    assert data["rpe"] == 7


def test_sets_update_no_fields(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set No Fields", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move L")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    set_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        json={},
        headers=user_auth_header,
    )
    assert res.status_code == 400
    assert res.json().get("detail") == "No fields provided"


def test_sets_update_unauthorized(client):
    res = client.patch(
        "/v1/workouts/1/exercises/1/sets/1",
        json={"repetitions": 8},
    )
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_sets_update_workout_not_found(client, user_auth_header):
    res = client.patch(
        "/v1/workouts/9999/exercises/1/sets/1",
        json={"repetitions": 8},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_sets_update_not_found(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Set Missing", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move M")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/9999",
        json={"repetitions": 8},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Set not found"


def test_sets_update_validation_error(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set Bad Update", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move N")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    set_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        json={"set_index": 0},
        headers=user_auth_header,
    )
    assert res.status_code == 422


def test_sets_update_index_conflict(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
    db_session,
    monkeypatch,
):
    workout_res = create_workout(name="Set Conflict Update", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move O")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res1 = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    set_id = res1.json()["id"]

    def _raise():
        raise IntegrityError("stmt", "params", Exception("orig"))

    monkeypatch.setattr(db_session, "commit", _raise)

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        json={"set_index": 1},
        headers=user_auth_header,
    )
    assert res.status_code == 409
    assert res.json().get("detail") == "Set index conflict"
