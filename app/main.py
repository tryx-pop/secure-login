"""Mini application de login sécurisée.

Protections principales :
- Mots de passe hachés avec Argon2id (jamais stockés en clair)
- Noms d'utilisateur chiffrés au repos (Fernet) + index aveugle HMAC pour la recherche
- Protection CSRF, rate limiting, cookies de session durcis, en-têtes de sécurité
- Base PostgreSQL managée (sauvegardes + restauration à un instant donné chez le fournisseur)
- Vérification du mot de passe contre une liste de mots de passe courants (SecLists)
"""
import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import Column, DateTime, Integer, LargeBinary, MetaData, String, Table, create_engine, func
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

COMMON_PASSWORDS_FILE = Path(os.environ.get("COMMON_PASSWORDS_FILE", "/app/common-passwords.txt"))
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


app = Flask(__name__)
app.config.update(
    SECRET_KEY=require_env("SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 min
    MAX_CONTENT_LENGTH=16 * 1024,
)

FERNET = Fernet(require_env("DATA_ENCRYPTION_KEY"))       # chiffre les noms d'utilisateur
INDEX_KEY = require_env("USERNAME_INDEX_KEY").encode()    # index aveugle (HMAC)
PH = PasswordHasher()  # Argon2id par défaut
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"], storage_uri="memory://")

COMMON_PASSWORDS = set()
if COMMON_PASSWORDS_FILE.exists():
    COMMON_PASSWORDS = {
        line.strip() for line in COMMON_PASSWORDS_FILE.read_text(errors="ignore").splitlines() if line.strip()
    }


# ---------- Base de données (PostgreSQL en prod, SQLite possible en test) ----------
# Exemple : postgresql+psycopg://user:pass@host:5432/db?sslmode=require
engine = create_engine(require_env("DATABASE_URL"), pool_pre_ping=True)
metadata = MetaData()
users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username_idx", String(64), unique=True, nullable=False),
    Column("username_enc", LargeBinary, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)


def init_db():
    metadata.create_all(engine)


def username_index(username: str) -> str:
    return hmac.new(INDEX_KEY, username.lower().encode(), hashlib.sha256).hexdigest()


def validate_password(pw: str):
    if len(pw) < 16:
        return "Le mot de passe doit contenir au moins 16 caractères."
    if not re.search(r"[A-Z]", pw):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"\d", pw):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Le mot de passe doit contenir au moins un caractère spécial."
    if pw in COMMON_PASSWORDS:
        return "Ce mot de passe est dans la liste des mots de passe courants."
    return None


# ---------- En-têtes de sécurité ----------
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- Routes ----------
@app.route("/health")
@limiter.exempt
def health():
    return {"status": "ok"}


@app.route("/")
def index():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        err = validate_password(password)
        if not USERNAME_RE.match(username):
            flash("Nom invalide (3-32 caractères : lettres, chiffres, _ . -).")
        elif err:
            flash(err)
        else:
            try:
                with engine.begin() as conn:
                    conn.execute(insert(users).values(
                        username_idx=username_index(username),
                        username_enc=FERNET.encrypt(username.encode()),
                        password_hash=PH.hash(password),
                    ))
                flash("Compte créé. Vous pouvez vous connecter.")
                return redirect(url_for("login"))
            except IntegrityError:
                flash("Impossible de créer ce compte.")  # message volontairement vague
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with engine.connect() as conn:
            row = conn.execute(
                select(users.c.id, users.c.password_hash).where(users.c.username_idx == username_index(username))
            ).first()
        try:
            # Hash factice si l'utilisateur n'existe pas : temps de réponse quasi constant
            PH.verify(row.password_hash if row else DUMMY_HASH, password)
            if row:
                if PH.check_needs_rehash(row.password_hash):
                    with engine.begin() as conn:
                        conn.execute(update(users).where(users.c.id == row.id).values(password_hash=PH.hash(password)))
                session.clear()
                session["uid"] = row.id
                session.permanent = True
                return redirect(url_for("dashboard"))
        except VerifyMismatchError:
            pass
        flash("Identifiants incorrects.")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))
    with engine.connect() as conn:
        row = conn.execute(select(users.c.username_enc).where(users.c.id == uid)).first()
    if row is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=FERNET.decrypt(bytes(row.username_enc)).decode())


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


DUMMY_HASH = PH.hash(secrets.token_urlsafe(16))
init_db()

if __name__ == "__main__":  # dev uniquement ; en prod : gunicorn
    app.run(host="127.0.0.1", port=8080)
