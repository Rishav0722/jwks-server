"""JWKS server backed by SQLite."""
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization

import db


def int_to_base64(value):
    """Convert an integer to a Base64URL string (no padding)."""
    hex_str = format(value, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    raw = bytes.fromhex(hex_str)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


class JWKSServerHandler(BaseHTTPRequestHandler):
    """Handles POST /auth and GET /.well-known/jwks.json."""

    db_path = db.DB_FILE

    def _send(self, status, body=b"", content_type=None):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Issue a JWT signed with a valid (or expired) DB key."""
        parsed = urlparse(self.path)
        if parsed.path != "/auth":
            return self._send(405)
        expired = "expired" in parse_qs(parsed.query)

        conn = db.init_db(self.db_path)
        try:
            row = db.get_key(conn, expired=expired)
        finally:
            conn.close()
        if row is None:
            return self._send(500)

        kid, pem, exp = row
        private_key = serialization.load_pem_private_key(pem, password=None)
        token = jwt.encode({"user": "username", "exp": exp},
                           private_key, algorithm="RS256",
                           headers={"kid": str(kid)})
        return self._send(200, token.encode("utf-8"))

    def do_GET(self):
        """Serve all unexpired public keys as a JWKS."""
        if urlparse(self.path).path != "/.well-known/jwks.json":
            return self._send(405)

        conn = db.init_db(self.db_path)
        try:
            rows = db.get_valid_keys(conn)
        finally:
            conn.close()

        keys = []
        for kid, pem in rows:
            nums = (serialization.load_pem_private_key(pem, password=None)
                    .public_key().public_numbers())
            keys.append({
                "alg": "RS256", "kty": "RSA", "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(nums.n), "e": int_to_base64(nums.e),
            })
        return self._send(200, json.dumps({"keys": keys}).encode("utf-8"),
                          "application/json")

    def _not_allowed(self):
        self._send(405)

    do_PUT = do_DELETE = do_PATCH = do_HEAD = _not_allowed


def run(port=8080):  # pragma: no cover
    """Seed the DB and start the server."""
    conn = db.init_db()
    db.ensure_keys(conn)
    conn.close()
    httpd = HTTPServer(("localhost", port), JWKSServerHandler)
    print(f"Server started on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    run()
