def test_exercises_create_success_admin(client, admin_auth_header, exercise_payload):
    payload = exercise_payload(name="Bench Press")
    res = client.post("/v1/exercises/", json=payload, headers=admin_auth_header)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Bench Press"
    assert data["primary_muscle"] == "chest"
    assert data["equipment"] == "barbell"
    assert data["is_active"] is True
    assert "created_at" in data
    assert "updated_at" in data


def test_exercises_create_forbidden_non_admin(client, user_auth_header, exercise_payload):
    res = client.post("/v1/exercises/", json=exercise_payload(), headers=user_auth_header)
    assert res.status_code == 403
    assert res.json().get("detail") == "Admin only"


def test_exercises_create_unauthorized(client, exercise_payload):
    res = client.post("/v1/exercises/", json=exercise_payload())
    assert res.status_code == 401
    assert res.json().get("detail") == "Not authenticated"


def test_exercises_create_duplicate_name(create_exercise):
    res1 = create_exercise(name="Bench Press")
    assert res1.status_code == 201

    res2 = create_exercise(name="Bench Press")
    assert res2.status_code == 409
    assert res2.json().get("detail") == "Exercise name already exists"


def test_exercises_create_validation_error(client, admin_auth_header, assert_missing_field):
    res = client.post(
        "/v1/exercises/",
        json={"primary_muscle": "chest", "equipment": "barbell"},
        headers=admin_auth_header,
    )
    assert_missing_field(res, "name")
