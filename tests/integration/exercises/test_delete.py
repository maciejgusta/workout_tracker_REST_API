from app.models.exercise import Exercise


def test_exercises_delete_success_admin(
    client, admin_auth_header, create_exercise_db, db_session
):
    exercise = create_exercise_db(name="Bench Press")

    res = client.delete(f"/v1/exercises/{exercise.id}", headers=admin_auth_header)
    assert res.status_code == 204

    db_session.expire_all()
    exercise_db = db_session.get(Exercise, exercise.id)
    assert exercise_db is not None
    assert exercise_db.is_active is False


def test_exercises_delete_unauthorized(client, create_exercise_db):
    exercise = create_exercise_db(name="Bench Press")
    res = client.delete(f"/v1/exercises/{exercise.id}")
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_exercises_delete_forbidden_non_admin(
    client, user_auth_header, create_exercise_db
):
    exercise = create_exercise_db(name="Bench Press")
    res = client.delete(f"/v1/exercises/{exercise.id}", headers=user_auth_header)
    assert res.status_code == 403
    assert res.json().get("detail") == "Admin only"


def test_exercises_delete_not_found(client, admin_auth_header):
    res = client.delete("/v1/exercises/9999", headers=admin_auth_header)
    assert res.status_code == 404
    assert res.json().get("detail") == "Exercise not found"
