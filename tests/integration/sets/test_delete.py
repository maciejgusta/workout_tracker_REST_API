def test_sets_delete_success_and_reorder(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    create_set,
    user_auth_header,
):
    workout_res = create_workout(name="Set Delete", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move P")
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
        workout_id, workout_exercise_id, headers=user_auth_header, repetitions=7
    )
    set_id = res2.json()["id"]
    assert res1.status_code == 201
    assert res2.status_code == 201
    assert res3.status_code == 201

    res = client.delete(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/{set_id}",
        headers=user_auth_header,
    )
    assert res.status_code == 204

    list_res = client.get(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets",
        headers=user_auth_header,
    )
    items = list_res.json()
    assert [item["repetitions"] for item in items] == [5, 7]
    assert [item["set_index"] for item in items] == [1, 2]


def test_sets_delete_unauthorized(client):
    res = client.delete("/v1/workouts/1/exercises/1/sets/1")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_sets_delete_workout_not_found(client, user_auth_header):
    res = client.delete(
        "/v1/workouts/9999/exercises/1/sets/1", headers=user_auth_header
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_sets_delete_not_found(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Set Missing Delete", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    exercise = create_exercise_db(name="Set Move Q")
    workout_exercise = create_workout_exercise(
        workout_id, exercise.id, headers=user_auth_header
    )
    workout_exercise_id = workout_exercise.json()["id"]

    res = client.delete(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}/sets/9999",
        headers=user_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Set not found"
