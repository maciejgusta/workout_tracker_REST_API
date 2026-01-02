import os
import pytest
from httpx import Response
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.db.database import engine
from app.dependencies import get_db
from app.main import app
from app.schemas.auth import Token
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.models.exercise import Exercise, ExerciseMuscle, ExerciseEquipment

@pytest.fixture(scope="session", autouse=True)
def migrate_db():
    alembic_cfg = Config("alembic.ini")
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")
    yield

@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(autocommit=False, autoflush=False, bind=connection)
    session = Session()
    try:
        yield session
    finally:
        if transaction.is_active:
            transaction.rollback()
        connection.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def create_user(client):
    def _create(username="test", password="testtest"):
        return client.post("/v1/auth/register", json={"username": username, "password": password})
    return _create

@pytest.fixture
def login_user(client):
    def _login(username="test", password="testtest"):
        return client.post("/v1/auth/login", data={"username": username, "password": password})
    return _login

@pytest.fixture
def assert_missing_field():
    def _assert_missing_field(res, field):
        assert res.status_code == 422
        errors = res.json().get("detail", [])
        assert any(
            error.get("loc") == ["body", field] and error.get("type") == "missing"
            for error in errors
        )
    return _assert_missing_field

@pytest.fixture
def auth_header():
    def _auth_header(res: Response) -> dict[str, str]:
        token_obj = Token.model_validate(res.json())
        return {"Authorization": f"Bearer {token_obj.access_token}"}
    return _auth_header

@pytest.fixture
def admin_user(db_session):
    user = User(
        username="admin",
        password_hash=hash_password("adminpass1"),
        role=UserRole.ADMIN,
    )
    db_session.add(user)
    db_session.commit()
    return user

@pytest.fixture
def login_admin(client, admin_user):
    def _login(username="admin", password="adminpass1"):
        return client.post("/v1/auth/login", data={"username": username, "password": password})
    return _login

@pytest.fixture
def admin_auth_header(login_admin, auth_header):
    res = login_admin()
    return auth_header(res)

@pytest.fixture
def user_auth_header(create_user, login_user, auth_header):
    create_user()
    res = login_user()
    return auth_header(res)

@pytest.fixture
def create_exercise_db(db_session):
    def _create(
        name="Bench Press",
        primary_muscle=ExerciseMuscle.CHEST,
        equipment=ExerciseEquipment.BARBELL,
        is_active=True,
    ):
        exercise = Exercise(
            name=name,
            primary_muscle=primary_muscle,
            equipment=equipment,
            is_active=is_active,
        )
        db_session.add(exercise)
        db_session.commit()
        db_session.refresh(exercise)
        return exercise
    return _create

@pytest.fixture
def exercise_payload():
    def _payload(
        name="Bench Press",
        primary_muscle="chest",
        equipment="barbell",
        is_active=True,
    ):
        payload = {
            "name": name,
            "primary_muscle": primary_muscle,
            "equipment": equipment,
        }
        if is_active is not None:
            payload["is_active"] = is_active
        return payload
    return _payload

@pytest.fixture
def create_exercise(client, admin_auth_header, exercise_payload):
    def _create(**kwargs):
        return client.post(
            "/v1/exercises/",
            json=exercise_payload(**kwargs),
            headers=admin_auth_header,
        )
    return _create
