"""Tests for the JWKS server and DB layer."""
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer

import jwt
import pytest

import db
import server


def call(url, method="GET"):
    """Make a request and return (status, body) even on HTTP errors."""
    req = urllib.request.Request(url, data=b"{}" if method == "POST" else None,
                                 method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def start_server(path):
    handler = type("H", (server.JWKSServerHandler,), {"db_path": path})
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_port}"


@pytest.fixture
def base(tmp_path):
    path = str(tmp_path / "t.db")
    conn = db.init_db(path)
    db.ensure_keys(conn)
    conn.close()
    httpd, url = start_server(path)
    yield url
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def empty_base(tmp_path):
    httpd, url = start_server(str(tmp_path / "empty.db"))
    yield url
    httpd.shutdown()
    httpd.server_close()


def jwks_keys(base):
    status, body = call(base + "/.well-known/jwks.json")
    assert status == 200
    return json.loads(body)["keys"]


def test_auth_returns_valid_jwt_verifiable_via_jwks(base):
    status, body = call(base + "/auth", "POST")
    assert status == 200
    token = body.decode()
    kid = jwt.get_unverified_header(token)["kid"]
    jwk = next(k for k in jwks_keys(base) if k["kid"] == kid)
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(token, pub, algorithms=["RS256"])
    assert claims["user"] == "username"


def test_auth_expired_uses_expired_key(base):
    status, body = call(base + "/auth?expired=true", "POST")
    assert status == 200
    token = body.decode()
    kid = jwt.get_unverified_header(token)["kid"]
    assert kid not in [k["kid"] for k in jwks_keys(base)]
    claims = jwt.decode(token, options={"verify_signature": False,
                                        "verify_exp": False})
    assert claims["exp"] <= time.time()


def test_jwks_only_contains_valid_keys(base):
    keys = jwks_keys(base)
    assert len(keys) == 1
    assert {"alg", "kty", "use", "kid", "n", "e"} <= set(keys[0])


def test_auth_500_when_no_key(empty_base):
    assert call(empty_base + "/auth", "POST")[0] == 500


def test_wrong_paths_and_methods(base):
    assert call(base + "/nope", "POST")[0] == 405
    assert call(base + "/nope")[0] == 405
    assert call(base + "/auth", "DELETE")[0] == 405
    assert call(base + "/auth", "PATCH")[0] == 405


def test_db_schema_and_ensure_keys_idempotent(tmp_path):
    conn = db.init_db(str(tmp_path / "x.db"))
    assert db.get_key(conn) is None
    db.ensure_keys(conn)
    db.ensure_keys(conn)
    assert conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0] == 2
    assert db.get_key(conn, expired=True)[2] <= time.time()
    assert db.get_key(conn)[2] > time.time()
    conn.close()


def test_int_to_base64():
    assert server.int_to_base64(65537) == "AQAB"
    assert server.int_to_base64(255) == "_w"
