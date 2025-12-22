from app.models.user import User
from app.core import security

def test_register_success(create_user, db_session):
    username = "test"
    password = "test"
    res = create_user(username=username, password=password)
    assert res.status_code == 201
    assert set(res.json().keys()) == {"id", "username", "created_at"}
    created_user = db_session.query(User).filter(User.username == username).first()
    assert created_user is not None
    assert created_user.username == username and security.verify_password(password, created_user.password_hash)

def test_register_user_exists(create_user):
    username = "test"
    password = "test"
    res1 = create_user(username=username, password=password)
    assert res1.status_code == 201
    assert res1.json().get("username") == username
    res2 = create_user(username=username, password=password)
    assert res2.status_code == 409
    assert res2.json().get("detail") == "Username already exists"