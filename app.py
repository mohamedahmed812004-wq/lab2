"""Lab 2 - Login & To-Do. Flask + PyMySQL (plain SQL, always parameterised) + bcrypt."""
import hmac
import os
import secrets
from functools import wraps

import bcrypt
import pymysql
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

MAX_NAME, MAX_EMAIL, MAX_TITLE, MAX_PASSWORD_BYTES = 100, 255, 200, 72  # bcrypt ignores > 72 bytes
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt(12))  # keeps login timing similar for unknown e-mails


# ---------------------------------------------------------------- database
def run(sql, params=(), fetch=None):
    """Run ONE statement. Values always travel in `params`, never inside the SQL text."""
    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "registration"),
        cursorclass=pymysql.cursors.DictCursor,
        charset="utf8mb4",
        autocommit=True,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
            if fetch == "id":
                return cur.lastrowid
            return cur.rowcount
    finally:
        conn.close()


# ---------------------------------------------------------------- security helpers
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def verify_csrf():
    if request.method == "POST":
        expected = session.get("csrf", "")
        sent = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(400)


@app.after_request
def no_cache(resp):
    # Stops the Back button from showing private pages after logout.
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


def start_session(user_id, name):
    session.clear()  # new session on every login
    session["user_id"] = user_id
    session["name"] = name


# ---------------------------------------------------------------- validation (same rules as static/app.js)
def title_error(title):
    if not title:
        return "Title is required"
    if len(title) > MAX_TITLE:
        return "Title is too long (200 characters at most)"
    return None


# ---------------------------------------------------------------- auth pages
@app.route("/")
def index():
    return redirect(url_for("todos" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("todos"))
    if request.method == "GET":
        return render_template("register.html", errors={}, form={})

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    errors = {}
    if not name:
        errors["name"] = "Name is required"
    elif len(name) > MAX_NAME:
        errors["name"] = "Name is too long (100 characters at most)"
    if not email:
        errors["email"] = "Email is required"
    elif len(email) > MAX_EMAIL:
        errors["email"] = "Email is too long (255 characters at most)"
    if not password:
        errors["password"] = "Password is required"
    elif len(password.encode()) > MAX_PASSWORD_BYTES:
        errors["password"] = "Password is too long (72 characters at most)"
    if not confirm:
        errors["confirm_password"] = "Confirm password is required"
    elif password and password != confirm:
        errors["confirm_password"] = "Passwords do not match"

    form = {"name": name, "email": email}
    if errors:  # R8: show the page again, do not touch the database
        return render_template("register.html", errors=errors, form=form), 422

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    try:
        user_id = run(
            "INSERT INTO users (email, name, password_hash) VALUES (%s, %s, %s)",
            (email, name, password_hash),
            fetch="id",
        )
    except pymysql.err.IntegrityError as exc:
        if exc.args[0] == 1062:  # duplicate entry -> UNIQUE (email)
            errors["email"] = "Email Already Exists"
            return render_template("register.html", errors=errors, form=form), 422
        raise

    start_session(user_id, name)
    return redirect(url_for("todos"))  # redirect after POST: refresh does not resend the form


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("todos"))
    if request.method == "GET":
        return render_template("login.html", errors={}, form={})

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    errors = {}
    if not email:
        errors["email"] = "Email is required"
    if not password:
        errors["password"] = "Password is required"
    if errors:
        return render_template("login.html", errors=errors, form={"email": email}), 422

    user = run(
        "SELECT user_id, name, password_hash FROM users WHERE email = %s", (email,), fetch="one"
    )
    stored = user["password_hash"].encode() if user else DUMMY_HASH
    try:
        ok = bcrypt.checkpw(password.encode()[:MAX_PASSWORD_BYTES], stored)
    except ValueError:
        ok = False
    if not user or not ok:  # same message for unknown e-mail and wrong password
        errors["form"] = "Invalid email or password"
        return render_template("login.html", errors=errors, form={"email": email}), 401

    start_session(user["user_id"], user["name"])
    return redirect(url_for("todos"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- to-do list (user_id always from the session)
def render_todos(add_value="", add_error=None, row_errors=None, row_values=None, status=200):
    rows = run(
        "SELECT todo_id, title, is_done, created_at FROM todos WHERE user_id = %s ORDER BY todo_id DESC",
        (session["user_id"],),
        fetch="all",
    )
    done = sum(1 for r in rows if r["is_done"])
    return (
        render_template(
            "todos.html",
            todos=rows,
            done_count=done,
            open_count=len(rows) - done,
            add_value=add_value,
            add_error=add_error,
            row_errors=row_errors or {},
            row_values=row_values or {},
        ),
        status,
    )


@app.get("/todos")
@login_required
def todos():
    return render_todos()


@app.post("/todos/add")
@login_required
def add_todo():
    title = request.form.get("title", "").strip()
    err = title_error(title)
    if err:
        return render_todos(add_value=request.form.get("title", ""), add_error=err, status=422)
    run("INSERT INTO todos (user_id, title) VALUES (%s, %s)", (session["user_id"], title))
    return redirect(url_for("todos"))


@app.post("/todos/<int:todo_id>/edit")
@login_required
def edit_todo(todo_id):
    title = request.form.get("title", "").strip()
    err = title_error(title)
    if err:
        return render_todos(
            row_errors={todo_id: err}, row_values={todo_id: request.form.get("title", "")}, status=422
        )
    run(
        "UPDATE todos SET title = %s WHERE todo_id = %s AND user_id = %s",
        (title, todo_id, session["user_id"]),
    )
    return redirect(url_for("todos"))


@app.post("/todos/<int:todo_id>/done")
@login_required
def set_done(todo_id):
    value = request.form.get("is_done")
    if value not in ("0", "1"):
        abort(400)
    run(
        "UPDATE todos SET is_done = %s WHERE todo_id = %s AND user_id = %s",
        (int(value), todo_id, session["user_id"]),
    )
    return redirect(url_for("todos"))


@app.post("/todos/<int:todo_id>/delete")
@login_required
def delete_todo(todo_id):
    run("DELETE FROM todos WHERE todo_id = %s AND user_id = %s", (todo_id, session["user_id"]))
    return redirect(url_for("todos"))


# ---------------------------------------------------------------- friendly error pages (no stack traces)
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def friendly_error(err):
    code = getattr(err, "code", 500) or 500
    messages = {
        400: "That request could not be processed. Go back and try again.",
        404: "We could not find that page.",
        405: "That action is not available here.",
        500: "Something went wrong on our side. Please try again in a moment.",
    }
    return render_template("error.html", code=code, message=messages.get(code, messages[500])), code


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
