from app.schemas.auth import Token
from app.core import security
from app.services.auth import validate_refresh_token
from httpx import Response

def assert_missing_field(res: Response, field: str):
    assert res.status_code == 422
    errors = res.json().get("detail", [])
    assert any(e["loc"] == ["body", field] and e["type"] == "missing" for e in errors)

def test_login_success(client, create_user, db_session):
    username = "test"
    password = "test"
    res1 = create_user(username=username, password=password)
    assert res1.status_code == 201
    assert "id" in res1.json().keys()
    user_id = res1.json().get("id")

    res2 = client.post("/v1/auth/login", data={"username": username, "password": password})
    assert res2.status_code == 200

    #access token check
    token_obj: Token = Token.model_validate(res2.json())
    assert token_obj.token_type == "bearer"
    access_token = token_obj.access_token
    payload = security.decode_token(access_token, token_type="access")
    assert payload is not None
    assert "sub" in payload.keys() and "typ" in payload.keys()
    assert payload["sub"] == str(user_id) and payload["typ"] == "access"

    #refresh token check
    assert res2.cookies.get("refresh_token") is not None
    refresh_token = res2.cookies.get("refresh_token")

    set_cookies = res2.headers.get_list("set-cookie")
    refresh_header = next(c for c in set_cookies if c.startswith("refresh_token=")).lower()
    assert "httponly" in refresh_header
    assert "path=/v1/auth/refresh" in refresh_header
    assert "samesite=lax" in refresh_header

    assert security.verify_refresh_token(refresh_token, validate_refresh_token(db_session, refresh_token).token_hash)

def test_login_invalid_credentials(client, create_user):
    username = "test"
    password = "test"
    bad_password = "TEST"
    res1 = create_user(username=username, password=password)
    assert res1.status_code == 201

    res2 = client.post("/v1/auth/login", data={"username": username, "password": bad_password})
    assert res2.status_code == 401
    assert res2.json().get("detail") == "Incorrect username or password"
    
def test_login_missing_password(client, assert_missing_field):
    res = client.post("/v1/auth/login", data={"username": "test"})
    assert_missing_field(res, "password")

def test_login_missing_username(client, assert_missing_field):
    res = client.post("/v1/auth/login", data={"password": "test"})
    assert_missing_field(res, "username")
