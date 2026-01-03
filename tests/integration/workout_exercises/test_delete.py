def test_workout_exercises_delete_success_and_reorder(
    client,
    create_workout,
    create_exercise_db,
    create_workout_exercise,
    user_auth_header,
):
    workout_res = create_workout(name="Delete Test", headers=user_auth_header)
    workout_id = workout_res.json()["id"]
    ex1 = create_exercise_db(name="Move A")
    ex2 = create_exercise_db(name="Move B")
    ex3 = create_exercise_db(name="Move C")

    res1 = create_workout_exercise(workout_id, ex1.id, headers=user_auth_header)
    res2 = create_workout_exercise(workout_id, ex2.id, headers=user_auth_header)
    res3 = create_workout_exercise(workout_id, ex3.id, headers=user_auth_header)
    workout_exercise_id = res2.json()["id"]
    assert res1.status_code == 201
    assert res2.status_code == 201
    assert res3.status_code == 201

    res = client.delete(
        f"/v1/workouts/{workout_id}/exercises/{workout_exercise_id}",
        headers=user_auth_header,
    )
    assert res.status_code == 204

    list_res = client.get(
        f"/v1/workouts/{workout_id}/exercises", headers=user_auth_header
    )
    items = list_res.json()
    assert [item["exercise_id"] for item in items] == [ex1.id, ex3.id]
    assert [item["position"] for item in items] == [1, 2]


def test_workout_exercises_delete_unauthorized(client):
    res = client.delete("/v1/workouts/1/exercises/1")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_workout_exercises_delete_workout_not_found(client, user_auth_header):
    res = client.delete("/v1/workouts/9999/exercises/1", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout not found"


def test_workout_exercises_delete_not_found(
    client,
    create_workout,
    user_auth_header,
):
    workout_res = create_workout(
        name="Missing Workout Exercise", headers=user_auth_header
    )
    workout_id = workout_res.json()["id"]

    res = client.delete(
        f"/v1/workouts/{workout_id}/exercises/9999", headers=user_auth_header
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Workout exercise not found"
