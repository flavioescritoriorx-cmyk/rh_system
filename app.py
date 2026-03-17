from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
from pathlib import Path

# ================= CONFIG =================
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "rh.db"

app = Flask(__name__)
app.secret_key = "rx_rh_system_2026_super_secret"


# ================= DATABASE =================
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # Garante que a pasta instance exista (ESSENCIAL no Render)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_conn()
    cur = conn.cursor()

    # Tabela de usuários
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL
        )
    """)

    # Tabela de funcionários
    cur.execute("""
        CREATE TABLE IF NOT EXISTS funcionarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            cargo TEXT,
            status TEXT
        )
    """)

    # Criar admin padrão
    cur.execute("SELECT * FROM usuarios WHERE usuario = ?", ("admin",))
    user = cur.fetchone()

    if not user:
        cur.execute("""
            INSERT INTO usuarios (nome, usuario, senha_hash)
            VALUES (?, ?, ?)
        """, (
            "Administrador",
            "admin",
            generate_password_hash("123456")
        ))

    # Dados iniciais
    cur.execute("SELECT COUNT(*) as total FROM funcionarios")
    total = cur.fetchone()["total"]

    if total == 0:
        cur.executemany("""
            INSERT INTO funcionarios (nome, cargo, status)
            VALUES (?, ?, ?)
        """, [
            ("FLAVIO CORREA", "ANALISTA", "Ativo"),
            ("MARIA SILVA", "RH", "Ativo"),
            ("JOAO SOUZA", "AUXILIAR", "Inativo"),
        ])

    conn.commit()
    conn.close()


# ================= AUTH =================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ================= ROTAS =================
@app.route("/")
def index():
    if "usuario_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        senha = request.form.get("senha")

        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["senha_hash"], senha):
            session["usuario_id"] = user["id"]
            session["usuario_nome"] = user["nome"]
            return redirect(url_for("dashboard"))
        else:
            flash("Usuário ou senha inválidos", "danger")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as total FROM funcionarios")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as total FROM funcionarios WHERE status = 'Ativo'")
    ativos = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as total FROM funcionarios WHERE status = 'Inativo'")
    inativos = cur.fetchone()["total"]

    conn.close()

    return render_template(
        "dashboard.html",
        total_funcionarios=total,
        ativos=ativos,
        inativos=inativos
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================= ERRO =================
@app.errorhandler(Exception)
def handle_exception(e):
    return f"Erro interno: {str(e)}", 500


# ================= START =================
init_db()

if __name__ == "__main__":
    app.run(debug=True)
