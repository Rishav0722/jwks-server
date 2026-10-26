"""SQLite-backed private key storage for the JWKS server."""
import sqlite3
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_FILE = "totally_not_my_privateKeys.db"


def init_db(path=DB_FILE):
    """Open (or create) the DB file and make sure the keys table exists."""
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )"""
    )
    conn.commit()
    return conn


def generate_and_save_key(conn, expired=False):
    """Generate an RSA key, store it as PKCS1 PEM, and return its kid."""
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    exp = int(time.time()) + (-3600 if expired else 3600)
    cur = conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                       (pem, exp))
    conn.commit()
    return cur.lastrowid


def get_key(conn, expired=False):
    """Return (kid, pem, exp) for one expired/unexpired key, or None."""
    now = int(time.time())
    if expired:
        cur = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,))
    else:
        cur = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,))
    return cur.fetchone()


def get_valid_keys(conn):
    """Return [(kid, pem), ...] for every unexpired key."""
    now = int(time.time())
    cur = conn.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    return cur.fetchall()


def ensure_keys(conn):
    """Make sure at least one valid and one expired key exist."""
    now = int(time.time())
    valid = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)).fetchone()[0]
    old = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)).fetchone()[0]
    if valid == 0:
        generate_and_save_key(conn, expired=False)
    if old == 0:
        generate_and_save_key(conn, expired=True)
