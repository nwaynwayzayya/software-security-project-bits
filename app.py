"""NoteVault web application with hardened local authentication and note access."""
import hashlib
import hmac
import os
import sqlite3

import jwt  # PyJWT
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
DB = "/tmp/notevault.db"
SECRET = os.environ.get("NOTEVAULT_SECRET")
if not SECRET:
    raise RuntimeError("NOTEVAULT_SECRET must be configured")

# Baseline used a single cookie name for both Flask's CSRF session and the JWT.
# resp.set_cookie("session", tok)
app.config.update(
    SECRET_KEY=SECRET,
    SESSION_COOKIE_NAME="flask_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
)
csrf = CSRFProtect(app)
# Keep Flask-WTF's server-side CSRF session separate from the signed auth token.
AUTH_COOKIE = "notevault_session"

# The marker keeps each team's local seed data traceable without affecting authorization.
TEAM_ID = os.environ.get("TEAM_ID", "unassigned")
TEAM_SALT = os.environ.get("TEAM_SALT", "notevault-anti-copy-dev-salt")


def team_marker():
    return hmac.new(TEAM_SALT.encode(), TEAM_ID.encode(), hashlib.sha256).hexdigest()[:12]


PAGE = """
<!doctype html><title>NoteVault</title>
<h1>NoteVault</h1>
{% if user %}<p>Signed in as <b>{{ user }}</b> · <a href="/logout">logout</a>
  {% if is_admin %}· <a href="/admin">admin</a>{% endif %}</p>
<form method=post action="/notes">
  <input type=hidden name=csrf_token value="{{ csrf_token() }}">
  <input name=title placeholder=title>
  <input name=body placeholder=note><button>Add note</button></form>
<h3>Your notes</h3>
<ul>
{% for note in notes %}
  <li>#{{ note["id"] }} <b>{{ note["title"] }}</b>: {{ note["body"] }}</li>
{% endfor %}
</ul>
<form action="/search"><input name=q placeholder="search notes"><button>Search</button></form>
{% else %}
<form method=post action="/login">
  <input type=hidden name=csrf_token value="{{ csrf_token() }}">
  user <input name=username> pass <input name=password type=password>
  <button>Login</button></form>
<form method=post action="/register">
  <input type=hidden name=csrf_token value="{{ csrf_token() }}">
  new: <input name=username> <input name=password type=password>
  <button>Register</button></form>
{% endif %}
"""


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def seed():
    con = db()
    con.executescript(
        "DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);"
    )
    # Baseline stored fast MD5 digests; password storage now uses Werkzeug's adaptive hash.
    # hashlib.md5(password.encode()).hexdigest()
    con.executemany("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    [("alice", generate_password_hash("alicepw"), "user"),
                     ("admin", generate_password_hash("admin123"), "admin")])
    con.executemany("INSERT INTO notes (owner, title, body) VALUES (?,?,?)",
                    [("alice", "groceries", "milk, eggs"),
                     ("admin", "infra", "prod db password is hunter2"),
                     ("admin", "build-tag", "team=%s marker=%s" % (TEAM_ID, team_marker()))])
    con.commit()
    con.close()


def current_user():
    # Baseline accepted the "none" JWT algorithm and used the exposed source secret.
    # data = jwt.decode(tok, baseline_secret, algorithms=["HS256", "none"])
    tok = request.cookies.get(AUTH_COOKIE, "")
    if not tok:
        return None
    try:
        data = jwt.decode(tok, SECRET, algorithms=["HS256"])
        username = data.get("sub")
        return username if isinstance(username, str) and role_of(username) else None
    except jwt.InvalidTokenError:
        return None


def role_of(username):
    con = db()
    r = con.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    return r["role"] if r else None


@app.route("/")
def home():
    user = current_user()
    rows = []
    if user:
        con = db()
        rows = con.execute("SELECT id,title,body FROM notes WHERE owner = ?", (user,)).fetchall()
        con.close()
    return render_template_string(
        PAGE,
        user=user,
        is_admin=(user and role_of(user) == "admin"),
        notes=rows,
    )


@app.route("/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or {}
    username = request.form.get("username") or payload.get("username")
    password = request.form.get("password") or payload.get("password")
    if not username or not password:
        return "username and password required", 400
    # Baseline trusted request.form["role"], allowing public admin registration.
    # role = request.form.get("role") or "user"
    con = db()
    try:
        # Public registration always creates a least-privileged account.
        con.execute(
            "INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (username, generate_password_hash(password), "user"),
        )
        con.commit()
    except sqlite3.IntegrityError:
        con.rollback()
        return "username already exists", 409
    finally:
        con.close()
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = request.form.get("username") or payload.get("username")
    password = request.form.get("password") or payload.get("password")
    # Baseline interpolated username and password into the SQL statement.
    # q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (...)
    con = db()
    row = con.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    con.close()
    # Baseline compared an MD5 digest directly; verify an adaptive password hash instead.
    # hashlib.md5((password or "").encode()).hexdigest()
    if not row or not check_password_hash(row["password"], password or ""):
        return "login failed", 401
    tok = jwt.encode({"sub": username}, SECRET, algorithm="HS256")
    if isinstance(tok, bytes):
        tok = tok.decode("ascii")
    resp = make_response(redirect("/"))
    # HttpOnly and SameSite reduce browser exposure; Secure is enabled for HTTPS deployments.
    resp.set_cookie(
        AUTH_COOKIE,
        tok,
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite="Lax",
    )
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie(AUTH_COOKIE)
    return resp


@app.route("/notes", methods=["POST"])
def add_note():
    user = current_user()
    if not user:
        return "auth required", 401
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    # The baseline also used parameterized insertion; CSRF protection now guards this POST.
    con = db()
    try:
        con.execute(
            "INSERT INTO notes (owner,title,body) VALUES (?,?,?)",
            (user, title, body),
        )
        con.commit()
    finally:
        con.close()
    return redirect("/")


@app.route("/api/notes/<int:nid>")
def api_note(nid):
    user = current_user()
    if not user:
        return jsonify(error="auth required"), 401
    # Baseline filtered only by note ID, so any authenticated user could read another owner.
    # SELECT ... FROM notes WHERE id = ?
    con = db()
    r = con.execute(
        """
        SELECT id, owner, title, body
        FROM notes
        WHERE id = ? AND owner = ?
        """,
        (nid, user),
    ).fetchone()
    con.close()
    return (jsonify(dict(r)) if r else (jsonify(error="not found"), 404))


@app.route("/search")
def search():
    user = current_user()
    if not user:
        return "auth required", 401
    term = request.args.get("q", "")
    # Baseline interpolated both the owner and search term into SQL.
    # q = "SELECT ... WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)
    con = db()
    rows = con.execute(
        """
        SELECT id, title, body
        FROM notes
        WHERE owner = ? AND body LIKE ?
        """,
        (user, f"%{term}%"),
    ).fetchall()
    con.close()
    return render_template_string(
        """
        <a href="/">back</a><ul>
        {% for note in notes %}
          <li>{{ note["title"] }}: {{ note["body"] }}</li>
        {% endfor %}
        </ul>
        """,
        notes=rows,
    )


@app.route("/admin")
def admin():
    user = current_user()
    if not user or role_of(user) != "admin":
        return "forbidden", 403
    # Baseline selected the password column and returned hashes to the client.
    # SELECT id, username, password, role FROM users
    con = db()
    rows = con.execute("SELECT id,username,role FROM users").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/export")
def export():
    if not current_user():
        return "auth required", 401
    # Baseline executed attacker-controlled fmt through subprocess with shell=True.
    # subprocess.run("echo exporting notes as " + fmt, shell=True, ...)
    fmt = request.args.get("fmt", "txt")
    if fmt != "txt":
        return "unsupported format", 400
    return "<pre>exporting notes as txt</pre>"


if __name__ == "__main__":
    seed()
    # Baseline enabled the Werkzeug debugger; keep debug disabled for all runtime modes.
    # app.run(host="0.0.0.0", port=8080, debug=True)
    app.run(
        host=os.environ.get("NOTEVAULT_HOST", "0.0.0.0"),
        port=int(os.environ.get("NOTEVAULT_PORT", "8080")),
        debug=False,
    )
