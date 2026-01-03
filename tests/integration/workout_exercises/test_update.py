from sqlalchemy.exc import IntegrityError


def test_workout_exercises_update_success_reorder(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Update Test", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    ex1 = create_exercise_db(name="Press A")
    ex2 = create_exercise_db(name="Press B")

    create_workout_exercise(workout_id, ex1.id, headers=user_auth_header)
    res2 = create_workout_exercise(workout_id, ex2.id, headers=user_auth_header)
    workout_exercise_id = res2.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={"position": 1},
        headers=user_auth_header,
    )

    assert res.status_code == 200
    assert res.json()["position"] == 1

    list_res = client.get(
        f"/v1/workouts/{workout_id}/exercises", headers=user_auth_header
    )
    items = list_res.json()
    assert [item["exercise_id"] for item in items] == [ex2.id, ex1.id]
    assert [item["position"] for item in items] == [1, 2]


def test_workout_exercises_update_success_change_exercise(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Change Exercise", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    ex1 = create_exercise_db(name="Curl A")
    ex2 = create_exercise_db(name="Curl B")

    res1 = create_workout_exercise(workout_id, ex1.id, headers=user_auth_header)
    workout_exercise_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={"exercise_id": ex2.id},
        headers=user_auth_header,
    )
    assert res.status_code == 200
    assert res.json()["exercise_id"] == ex2.id


def test_workout_exercises_update_no_fields(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="No Fields", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Row D")
    res1 = create_workout_exercise(workout_id, exercise.id, headers=user_auth_header)
    workout_exercise_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={},
        headers=user_auth_header,
    )
    assert res.status_code == 400
    assert res.json().get("detail") == "No fields provided"


def test_workout_exercises_update_invalid_exercise_id(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Invalid Exercise", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Row E")
    res1 = create_workout_exercise(workout_id, exercise.id, headers=user_auth_header)
    workout_exercise_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={"exercise_id": 99999},
        headers=user_auth_header,
    )
    assert res.status_code == 400
    assert res.json().get("detail") == "Exercise with the given id does not exist"


def test_workout_exercises_update_unauthorized(client):
    res = client.patch(
        "/v1/workouts/1/exercises/1",
        json={"position": 1},
    )
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workout_exercises_update_workout_not_found(client, user_auth_header):
    res = client.patch(
        "/v1/workouts/9999/exercises/1",
        json={"position": 1},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workout_exercises_update_not_found(
    client,
    create_workout,
    user_auth_header,
):
    workout_res = create_workout(name="Missing Exercise", headers=user_auth_header)
    workout_id = workout_res.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/9999",
        json={"position": 1},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout exercise not found"


def test_workout_exercises_update_validation_error(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Bad Update", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Row F")
    res1 = create_workout_exercise(workout_id, exercise.id, headers=user_auth_header)
    workout_exercise_id = res1.json()["id"]

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={"position": 0},
        headers=user_auth_header,
    )
    assert res.status_code == 422


def test_workout_exercises_update_position_conflict(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
    db_session,
    monkeypatch,
):
    workout_res = create_workout(name="Conflict Update", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Row G")
    res1 = create_workout_exercise(workout_id, exercise.id, headers=user_auth_header)
    workout_exercise_id = res1.json()["id"]

    def _raise():
        raise IntegrityError("stmt", "params", Exception("orig"))

    monkeypatch.setattr(db_session, "commit", _raise)

    res = client.patch(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        json={"position": 1},
        headers=user_auth_header,
    )
    assert res.status_code == 409
    assert res.json().get("detail") == "Failed to update exercise: position conflict"
