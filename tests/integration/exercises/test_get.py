def test_exercises_get_success_user(client, create_exercise_db, user_auth_header):
    exercise = create_exercise_db(name="Bench Press")

    res = client.get(f"/v1/exercises/{exercise.id}", headers=user_auth_header)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == exercise.id
    assert data["name"] == "Bench Press"
    assert "is_active" not in data
    assert "created_at" not in data
    assert "updated_at" not in data


def test_exercises_get_success_admin_inactive(
    client, create_exercise_db, admin_auth_header
):
    exercise = create_exercise_db(name="Hidden", is_active=False)

    res = client.get(f"/v1/exercises/{exercise.id}", headers=admin_auth_header)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == exercise.id
    assert data["is_active"] is False


def test_exercises_get_inactive_hidden_from_user(
    client, create_exercise_db, user_auth_header
):
    exercise = create_exercise_db(name="Hidden", is_active=False)

    res = client.get(f"/v1/exercises/{exercise.id}", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Exercise not found"


def test_exercises_get_not_found(client, user_auth_header):
    res = client.get("/v1/exercises/9999", headers=user_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Exercise not found"


def test_exercises_get_unauthorized(client):
    res = client.get("/v1/exercises/1")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_exercises_get_invalid_id(client, user_auth_header):
    res = client.get("/v1/exercises/abc", headers=user_auth_header)
    assert res.status_code == 422
