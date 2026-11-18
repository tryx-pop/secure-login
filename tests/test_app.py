import os
import sqlite3
import sys
import tempfile

from cryptography.fernet import Fernet

os.environ.update(
    SECRET_KEY="test", DATA_ENCRYPTION_KEY=Fernet.generate_key().decode(), USERNAME_INDEX_KEY="idx",
    COOKIE_SECURE="0", DATABASE_URL="sqlite:///" + os.path.join(tempfile.mkdtemp(), "t.db"), COMMON_PASSWORDS_FILE="/nonexistent",
)
sys.path.insert(0, "app")
import main  # noqa: E402

main.app.config["WTF_CSRF_ENABLED"] = False
main.limiter.enabled = False
c = main.app.test_client()


def test_register_login_and_hash_not_plaintext():
    assert c.post("/register", data={"username": "alice", "password": "Correct-Horse-Battery42!"}).status_code == 302
    row = sqlite3.connect(os.environ["DATABASE_URL"].replace("sqlite:///", "")).execute("SELECT username_enc, password_hash FROM users").fetchone()
    assert b"alice" not in row[0] and row[1].startswith("$argon2id$")
    assert c.post("/login", data={"username": "alice", "password": "Correct-Horse-Battery42!"}).status_code == 302
    assert c.post("/login", data={"username": "alice", "password": "wrong"}).status_code == 200


def test_weak_password_rejected():
    r = c.post("/register", data={"username": "bob", "password": "short"})
    assert "16 caractères".encode() in r.data


def test_password_policy():
    v = main.validate_password
    assert v("Abcdefghijklmnop1!") is None
    assert "majuscule" in v("abcdefghijklmnop1!")
    assert "chiffre" in v("Abcdefghijklmnopq!")
    assert "spécial" in v("Abcdefghijklmnop12")
    assert "16" in v("Abc1!")


def test_health_and_headers():
    r = c.get("/health")
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
