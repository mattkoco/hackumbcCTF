import os
import base64
import sqlite3
from pathlib import Path
from flask import (
    Flask, request, jsonify, session,
    send_from_directory, redirect, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "app.db"))
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "veryrealpassword123")

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # set True when serving over HTTPS
)

# ----------------------- DB (keeps login “real”, but not required) -----------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
            )

# ----------------------- Cookie-based admin gate (documented in /docs) ------------------
def _b64url_decode(s: str) -> str:
    # tolerate missing padding
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad).decode("utf-8", "ignore")

def cookie_admin_claim() -> tuple[bool, str | None]:
    token = request.cookies.get("tg_session")
    if not token:
        return (False, None)
    try:
        raw = _b64url_decode(token)
        # expected format: username:role:umbc1966
        parts = raw.split(":")
        if len(parts) != 3:
            return (False, None)
        username, role, marker = parts
        if marker != "umbc1966":
            return (False, None)
        if role.lower() == "admin":
            return (True, username or "admin")
        return (False, None)
    except Exception:
        return (False, None)

def is_admin_request() -> bool:
    if session.get("is_admin"):
        return True
    ok, _ = cookie_admin_claim()
    return ok

# ----------------------- API (login is a decoy but works) --------------------------------
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Missing credentials."}), 400

    with get_db() as conn:
        cur = conn.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
            (username,),
        )
        user = cur.fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401

    if not bool(user["is_admin"]):
        return jsonify({"ok": False, "error": "Account not permitted."}), 403

    session.clear()
    session["user_id"] = int(user["id"])
    session["username"] = user["username"]
    session["is_admin"] = True

    return jsonify({"ok": True, "username": user["username"], "is_admin": True})

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/me")
def me():
    admin_cookie, cookie_user = cookie_admin_claim()
    return jsonify({
        "authenticated": bool(session.get("user_id")) or admin_cookie,
        "username": session.get("username") or cookie_user,
        "is_admin": bool(session.get("is_admin", False)) or admin_cookie,
    })

# ----------------------- Pages -----------------------------------------------------------
@app.get("/")
def root():
    return redirect("/index")

@app.get("/index")
def index_page():
    return send_from_directory(BASE_DIR, "index.html")

@app.get("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")

@app.get("/admin")
def admin_page():
    if not is_admin_request():
        return redirect(url_for("login_page"))
    return send_from_directory(BASE_DIR, "admin.html")

@app.get("/docs")
def docs_page():
    return send_from_directory(BASE_DIR, "docs.html")

# Static passthrough for other files (css/js/images)
@app.get("/<path:filename>")
def static_files(filename: str):
    file_path = (BASE_DIR / filename).resolve()
    if BASE_DIR not in file_path.parents or not file_path.exists() or not file_path.is_file():
        return redirect("/index")
    rel = file_path.relative_to(BASE_DIR)
    return send_from_directory(BASE_DIR, str(rel))

# ----------------------- Entrypoint ------------------------------------------------------
if __name__ == "__main__":
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db()
    app.run(host="127.0.0.1", port=3000)
