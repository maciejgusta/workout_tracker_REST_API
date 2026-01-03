from fastapi import HTTPException
from app.services import sets as sets_service


def test_sets_create_success_user(
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Sets Create", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move D")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = create_set(
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=5
    )
    assert res.status_code == 201
    data = res.json()
    assert data["workout_exercise_id"] == workout_exercise_id
    assert data["set_index"] == 1
    assert data["repetitions"] == 5
    assert "created_at" not in data
    assert "updated_at" not in data


def test_sets_create_success_admin_sees_metadata(
    create_user,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    admin_auth_header,
):
    user_res = create_user(username="user_sets_admin_create", password="testtest")
    workout_res = create_workout(
        name="Admin Sets Create",
        user_id=user_res.json()["id"],
        headers=admin_auth_header,
    )
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move E")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=admin_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = create_set(
        workout_id, workout_exercise_id, headers=admin_auth_header, repetitions=6
    )
    assert res.status_code == 201
    data = res.json()
    assert "created_at" in data
    assert "updated_at" in data


def test_sets_create_set_index_inserts(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set Insert", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move F")
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
    res3 = create_set(
        workout_id,
        workout_exercise_id,
        headers=user_auth_header,
        repetitions=7,
        set_index=1,
    )
    assert res1.status_code == 201
    assert res2.status_code == 201
    assert res3.status_code == 201

    res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=user_auth_header,
    )
    items = res.json()
    assert [item["set_index"] for item in items] == [1, 2, 3]
    assert [item["repetitions"] for item in items] == [7, 5, 6]


def test_sets_create_unauthorized(client):
    res = client.post(
        "/v1/workouts/1/exercises/1/sets",
        json={"repetitions": 5},
    )
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_sets_create_workout_not_found(client, user_auth_header):
    res = client.post(
        "/v1/workouts/9999/exercises/1/sets",
        json={"repetitions": 5},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_sets_create_workout_exercise_not_found(
    client,
    create_workout,
    user_auth_header,
):
    workout_res = create_workout(name="Missing WE", headers=user_auth_header)
    workout_id = workout_res.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises/9999/sets",
        json={"repetitions": 5},
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout exercise not found"


def test_sets_create_validation_error(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
    assert_missing_field,
):
    workout_res = create_workout(name="Set Missing Field", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move G")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        json={},
        headers=user_auth_header,
    )
    assert_missing_field(res, "repetitions")


def test_sets_create_rpe_validation_error(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Set Bad RPE", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move H")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        json={"repetitions": 5, "rpe": 11},
        headers=user_auth_header,
    )
    assert res.status_code == 422


def test_sets_create_conflict(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
    monkeypatch,
):
    def _raise(*_args, **_kwargs):
        raise HTTPException(status_code=409, detail="Set index conflict")

    monkeypatch.setattr(sets_service, "create_one", _raise)

    workout_res = create_workout(name="Set Conflict", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move I")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = client.post(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        json={"repetitions": 5},
        headers=user_auth_header,
    )
    assert res.status_code == 409
    assert res.json().get("detail") == "Set index conflict"
