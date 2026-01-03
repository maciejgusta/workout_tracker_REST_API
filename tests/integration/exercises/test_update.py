def test_exercises_update_success_admin(client, admin_auth_header, create_exercise_db):
    exercise = create_exercise_db(name="Bench Press")

    res = client.patch(
        f"/v1/exercises/{exercise.id}",
        json={"name": "Incline Bench"},
        headers=admin_auth_header,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == exercise.id
    assert data["name"] == "Incline Bench"


def test_exercises_update_no_fields(client, admin_auth_header, create_exercise_db):
    exercise = create_exercise_db(name="Bench Press")

    res = client.patch(
        f"/v1/exercises/{exercise.id}",
        json={},
        headers=admin_auth_header,
    )
    assert res.status_code == 400
    assert res.json().get("detail") == "No fields provided"


def test_exercises_update_unauthorized(client, create_exercise_db):
    exercise = create_exercise_db(name="Bench Press")
    res = client.patch(f"/v1/exercises/{exercise.id}", json={"name": "New Name"})
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_exercises_update_forbidden_non_admin(
    client, user_auth_header, create_exercise_db
):
    exercise = create_exercise_db(name="Bench Press")
    res = client.patch(
        f"/v1/exercises/{exercise.id}",
        json={"name": "New Name"},
        headers=user_auth_header,
    )
    assert res.status_code == 403
    assert res.json().get("detail") == "Admin only"


def test_exercises_update_not_found(client, admin_auth_header):
    res = client.patch(
        "/v1/exercises/9999",
        json={"name": "Missing"},
        headers=admin_auth_header,
    )
    assert res.status_code == 404
    assert res.json().get("detail") == "Exercise not found"


def test_exercises_update_conflict_name(client, admin_auth_header, create_exercise_db):
    create_exercise_db(name="Bench Press")
    exercise = create_exercise_db(name="Squat")

    res = client.patch(
        f"/v1/exercises/{exercise.id}",
        json={"name": "Bench Press"},
        headers=admin_auth_header,
    )
    assert res.status_code == 409
    assert res.json().get("detail") == "Exercise name already exists"


def test_exercises_update_validation_error(
    client, admin_auth_header, create_exercise_db
):
    exercise = create_exercise_db(name="Bench Press")

    res = client.patch(
        f"/v1/exercises/{exercise.id}",
        json={"equipment": "invalid"},
        headers=admin_auth_header,
    )
    assert res.status_code == 422
