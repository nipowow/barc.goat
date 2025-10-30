from flask import Blueprint, abort, render_template, request, redirect, url_for
from flask_login import UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from flask import g, current_app
from . import login_manager, bcrypt 

auth = Blueprint("auth", __name__, template_folder="templates")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@auth.teardown_app_request
def close_db(exc):
    db = g.pop("db", None)
    if db: db.close()

class User(UserMixin):
    def __init__(self, id_usuario, nombre, contrasena):
        self.id = id_usuario
        self.username = nombre
        self.password_hash = contrasena

    @staticmethod
    def from_row(row):
        return User(row["id_usuario"], row["nombre"], row["contrasena"]) if row else None

@login_manager.user_loader
def load_user(user_id):
    row = get_db().execute(
        "SELECT id_usuario, nombre, contrasena FROM usuario WHERE id_usuario = ?",
        (user_id,)
    ).fetchone()
    return User.from_row(row)

# --- Vistas GET (formularios) ---
@auth.get("/login")
def login_get():
    return render_template("login.html")

@auth.get("/register")
def register_get():
    return render_template("register.html")

# --- POST login/registro ---
@auth.post("/register")
def register_post():
    username = request.form["username"].strip()
    password = request.form["password"]

    exists = get_db().execute(
        "SELECT 1 FROM usuario WHERE nombre = ?",
        (username,)
    ).fetchone()
    if exists:
        return "El usuario ya existe", 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    get_db().execute("""
        INSERT INTO usuario (nombre, contrasena, fecha_nacimiento, direccion, telefono, tipo_usuario)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (username, hashed_pw, "2000-01-01", "Sin dirección", 0, "Usuario"))
    get_db().commit()

    row = get_db().execute(
        "SELECT id_usuario, nombre, contrasena FROM usuario WHERE nombre = ?",
        (username,)
    ).fetchone()
    login_user(User.from_row(row))
    return redirect(url_for("main.index"))

@auth.post("/login")
def login_post():
    username = request.form["username"].strip()
    password = request.form["password"]

    row = get_db().execute(
        "SELECT id_usuario, nombre, contrasena FROM usuario WHERE nombre = ?",
        (username,)
    ).fetchone()
    if not row:
        return abort(404) 

    user = User.from_row(row)
    stored = user.password_hash or ""
    is_bcrypt = stored.startswith("$2")
    ok = bcrypt.check_password_hash(stored, password) if is_bcrypt else (stored == password)
    if not ok:
        return "Usuario o contraseña incorrectos", 401

    login_user(user)
    return redirect(url_for("main.profile"))



@auth.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login_get"))