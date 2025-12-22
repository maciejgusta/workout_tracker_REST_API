import os
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.db.database import engine
from app.dependencies import get_db
from app.main import app

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
        session.close()
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
    def _create(username="test", password="test"):
        return client.post("/v1/auth/register", json={"username": username, "password": password})
    return _create

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
