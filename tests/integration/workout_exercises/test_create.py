from fastapi import HTTPException
from app.services import workout_exercises as workout_exercises_service


def test_workout_exercises_create_success_user(
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Push Day", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Bench Press B")

    res = create_workout_exercise(workout_id, exercise.id, headers=user_auth_header)
    assert res.status_code == 201
    data = res.json()
    assert data["workout_id"] == workout_id
    assert data["exercise_id"] == exercise.id
    assert data["position"] == 1
    assert set(data.keys()) == {"id", "workout_id", "exercise_id", "position"}


def test_workout_exercises_create_success_admin_other_user(
    create_user,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    admin_auth_header,
):
    user_res = create_user(username="user_we_c", password="testtest")
    workout_res = create_workout(
        name="Admin Plan", user_id=user_res.json()["id"], headers=admin_auth_header
    )
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Bench Press C")

    res = create_workout_exercise(workout_id, exercise.id, headers=admin_auth_header)
    assert res.status_code == 201
    data = res.json()
    assert data["exercise_id"] == exercise.id
    assert "created_at" in data
    assert "updated_at" in data


def test_workout_exercises_create_position_inserts(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Insert Test", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    ex1 = create_exercise_db(name="Row A")
    ex2 = create_exercise_db(name="Row B")
    ex3 = create_exercise_db(name="Row C")

    res1 = create_workout_exercise(workout_id, ex1.id, headers=user_auth_header)
    res2 = create_workout_exercise(workout_id, ex2.id, headers=user_auth_header)
    res3 = create_workout_exercise(
        workout_id, ex3.id, headers=user_auth_header, position=2
    )
    assert res1.status_code == 201
    assert res2.status_code == 201
    assert res3.status_code == 201

    res = client.get(f"/v1/workouts/{workout_id}/exercises", headers=user_auth_header)
    items = res.json()
    assert [item["exercise_id"] for item in items] == [ex1.id, ex3.id, ex2.id]
    assert [item["position"] for item in items] == [1, 2, 3]


def test_workout_exercises_create_unauthorized(client, create_exercise_db):
    exercise = create_exercise_db(name="Bench Press D")
    res = client.post(
        "/v1/workouts/1/exercises",
        json={"exercise_id": exercise.id},
    )
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workout_exercises_create_workout_not_found(
    client,
    create_exercise_db,
    user_auth_header,
):
    exercise = create_exercise_db(name="Bench Press E")
    res = client.post(
        "/v1/workouts/9999/exercises",
        json={"exercise_id": exercise.id},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workout_exercises_create_exercise_not_found(
    client,
    create_workout,
    user_auth_header,
):
    workout_res = create_workout(name="Missing Exercise", headers=user_auth_header)
    workout_id = workout_res.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises",
        json={"exercise_id": 99999},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Exercise not found"


def test_workout_exercises_create_validation_error(
    client,
    create_workout,
    user_auth_header,
    assert_missing_field,
):
    workout_res = create_workout(name="Missing Field", headers=user_auth_header)
    workout_id = workout_res.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises",
        json={},
        headers=user_auth_header,
    )
    assert_missing_field(res, "exercise_id")


def test_workout_exercises_create_position_validation_error(
    client,
    create_workout,
    create_exercise_db,
    user_auth_header,
):
    workout_res = create_workout(name="Bad Position", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Bench Press F")

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises",
        json={"exercise_id": exercise.id, "position": 0},
        headers=user_auth_header,
    )
    assert res.status_code == 422


def test_workout_exercises_create_position_conflict(
    client,
    create_workout,
    create_exercise_db,
    user_auth_header,
    monkeypatch,
):
    def _raise(*_args, **_kwargs):
        raise HTTPException(
            status_code=409,
            detail="Position not unique",
        )

    monkeypatch.setattr(workout_exercises_service, "create_one", _raise)
    workout_res = create_workout(name="Conflict", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Bench Press G")

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises",
        json={"exercise_id": exercise.id},
        headers=user_auth_header,
    )
    assert res.status_code == 409
    assert res.json().get("detail") == "Position not unique"
