from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "rh.db"

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "doc", "docx"}
STATUS_OPTIONS = ["Ativo", "Inativo", "Afastado"]
PROFILE_OPTIONS = ["admin", "rh"]

app = Flask(__name__)
app.config["SECRET_KEY"] = "troque-esta-chave-em-producao"
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# ---------------------------
# DB
# ---------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    INSTANCE_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL DEFAULT 'rh',
            ativo INTEGER NOT NULL DEFAULT 1,
            criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS funcionarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            cargo TEXT,
            cpf TEXT UNIQUE,
            data_admissao TEXT,
            telefone TEXT,
            email TEXT,
            status TEXT NOT NULL DEFAULT 'Ativo',
            centro_custo TEXT,
            possui_carteira INTEGER NOT NULL DEFAULT 0,
            salario REAL,
            observacoes TEXT,
            criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS documentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            funcionario_id INTEGER NOT NULL,
            tipo_documento TEXT NOT NULL,
            nome_arquivo TEXT NOT NULL,
            caminho_arquivo TEXT NOT NULL,
            enviado_por INTEGER,
            enviado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (funcionario_id) REFERENCES funcionarios(id),
            FOREIGN KEY (enviado_por) REFERENCES usuarios(id)
        )
        """
    )

    cur.execute("SELECT id FROM usuarios WHERE usuario = ?", ("admin",))
    if cur.fetchone() is None:
        cur.execute(
            """
            INSERT INTO usuarios (nome, usuario, senha_hash, perfil, ativo)
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                "Administrador",
                "admin",
                generate_password_hash("123456"),
                "admin",
            ),
        )

    conn.commit()
    conn.close()


# ---------------------------
# Helpers
# ---------------------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para acessar o sistema.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("perfil") != "admin":
            flash("Acesso restrito ao administrador.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def parse_currency(value: str | None) -> float | None:
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    raw = raw.replace("R$", "").replace(".", "").replace(",", ".").strip()
    try:
        return float(raw)
    except ValueError:
        return None


def format_currency(value: float | None) -> str:
    if value is None:
        return ""
    txt = f"{value:,.2f}"
    return "R$ " + txt.replace(",", "X").replace(".", ",").replace("X", ".")


@app.context_processor
def inject_globals():
    return {
        "STATUS_OPTIONS": STATUS_OPTIONS,
        "PROFILE_OPTIONS": PROFILE_OPTIONS,
        "format_currency": format_currency,
        "now_year": datetime.now().year,
    }


# ---------------------------
# Auth
# ---------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        senha = request.form.get("senha", "")

        user = get_db().execute(
            "SELECT * FROM usuarios WHERE usuario = ? AND ativo = 1", (usuario,)
        ).fetchone()

        if user and check_password_hash(user["senha_hash"], senha):
            session["user_id"] = user["id"]
            session["nome"] = user["nome"]
            session["usuario"] = user["usuario"]
            session["perfil"] = user["perfil"]
            flash("Login realizado com sucesso.", "success")
            return redirect(url_for("dashboard"))

        flash("Usuário ou senha inválidos.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("login"))


@app.route("/alterar-senha", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        atual = request.form.get("senha_atual", "")
        nova = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        db = get_db()
        user = db.execute("SELECT * FROM usuarios WHERE id = ?", (session["user_id"],)).fetchone()

        if not check_password_hash(user["senha_hash"], atual):
            flash("Senha atual incorreta.", "danger")
        elif len(nova) < 6:
            flash("A nova senha deve ter pelo menos 6 caracteres.", "warning")
        elif nova != confirmar:
            flash("A confirmação da nova senha não confere.", "warning")
        else:
            db.execute(
                "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                (generate_password_hash(nova), session["user_id"]),
            )
            db.commit()
            flash("Senha alterada com sucesso.", "success")
            return redirect(url_for("dashboard"))

    return render_template("change_password.html")


# ---------------------------
# Dashboard
# ---------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    total_func = db.execute("SELECT COUNT(*) total FROM funcionarios").fetchone()["total"]
    ativos = db.execute(
        "SELECT COUNT(*) total FROM funcionarios WHERE status = 'Ativo'"
    ).fetchone()["total"]
    inativos = db.execute(
        "SELECT COUNT(*) total FROM funcionarios WHERE status = 'Inativo'"
    ).fetchone()["total"]
    afastados = db.execute(
        "SELECT COUNT(*) total FROM funcionarios WHERE status = 'Afastado'"
    ).fetchone()["total"]
    com_carteira = db.execute(
        "SELECT COUNT(*) total FROM funcionarios WHERE possui_carteira = 1"
    ).fetchone()["total"]
    docs_count = db.execute("SELECT COUNT(*) total FROM documentos").fetchone()["total"]

    por_status = db.execute(
        "SELECT status, COUNT(*) total FROM funcionarios GROUP BY status ORDER BY total DESC"
    ).fetchall()
    por_centro = db.execute(
        """
        SELECT COALESCE(NULLIF(centro_custo, ''), 'Não informado') centro, COUNT(*) total
        FROM funcionarios
        GROUP BY COALESCE(NULLIF(centro_custo, ''), 'Não informado')
        ORDER BY total DESC, centro ASC
        """
    ).fetchall()

    recentes = db.execute(
        "SELECT * FROM funcionarios ORDER BY id DESC LIMIT 5"
    ).fetchall()

    return render_template(
        "dashboard.html",
        total_func=total_func,
        ativos=ativos,
        inativos=inativos,
        afastados=afastados,
        com_carteira=com_carteira,
        docs_count=docs_count,
        por_status=por_status,
        por_centro=por_centro,
        recentes=recentes,
    )


# ---------------------------
# Funcionários
# ---------------------------
@app.route("/funcionarios")
@login_required
def employees():
    busca = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()

    sql = "SELECT * FROM funcionarios WHERE 1=1"
    params: list = []

    if busca:
        sql += " AND (nome LIKE ? OR cargo LIKE ? OR cpf LIKE ? OR centro_custo LIKE ?)"
        like = f"%{busca}%"
        params.extend([like, like, like, like])

    if status:
        sql += " AND status = ?"
        params.append(status)

    sql += " ORDER BY nome ASC"

    rows = get_db().execute(sql, params).fetchall()
    return render_template("employees.html", rows=rows, busca=busca, filtro_status=status)


@app.route("/funcionarios/novo", methods=["GET", "POST"])
@login_required
def employee_create():
    if request.method == "POST":
        db = get_db()
        data = _employee_form_data(request)
        try:
            db.execute(
                """
                INSERT INTO funcionarios
                (nome, cargo, cpf, data_admissao, telefone, email, status, centro_custo,
                 possui_carteira, salario, observacoes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                data,
            )
            db.commit()
            flash("Funcionário cadastrado com sucesso.", "success")
            return redirect(url_for("employees"))
        except sqlite3.IntegrityError:
            flash("CPF já cadastrado para outro funcionário.", "danger")

    return render_template("employee_form.html", item=None)


@app.route("/funcionarios/<int:employee_id>")
@login_required
def employee_detail(employee_id: int):
    db = get_db()
    item = db.execute("SELECT * FROM funcionarios WHERE id = ?", (employee_id,)).fetchone()
    if item is None:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("employees"))

    docs = db.execute(
        """
        SELECT d.*, u.nome AS usuario_nome
        FROM documentos d
        LEFT JOIN usuarios u ON u.id = d.enviado_por
        WHERE d.funcionario_id = ?
        ORDER BY d.id DESC
        """,
        (employee_id,),
    ).fetchall()
    return render_template("employee_detail.html", item=item, docs=docs)


@app.route("/funcionarios/<int:employee_id>/editar", methods=["GET", "POST"])
@login_required
def employee_edit(employee_id: int):
    db = get_db()
    item = db.execute("SELECT * FROM funcionarios WHERE id = ?", (employee_id,)).fetchone()
    if item is None:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("employees"))

    if request.method == "POST":
        data = _employee_form_data(request)
        try:
            db.execute(
                """
                UPDATE funcionarios
                SET nome = ?, cargo = ?, cpf = ?, data_admissao = ?, telefone = ?, email = ?,
                    status = ?, centro_custo = ?, possui_carteira = ?, salario = ?, observacoes = ?
                WHERE id = ?
                """,
                (*data, employee_id),
            )
            db.commit()
            flash("Funcionário atualizado com sucesso.", "success")
            return redirect(url_for("employee_detail", employee_id=employee_id))
        except sqlite3.IntegrityError:
            flash("CPF já cadastrado para outro funcionário.", "danger")

    return render_template("employee_form.html", item=item)


@app.route("/funcionarios/<int:employee_id>/excluir", methods=["POST"])
@login_required
def employee_delete(employee_id: int):
    db = get_db()
    item = db.execute("SELECT * FROM funcionarios WHERE id = ?", (employee_id,)).fetchone()
    if item is None:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("employees"))

    docs = db.execute(
        "SELECT * FROM documentos WHERE funcionario_id = ?", (employee_id,)
    ).fetchall()
    for doc in docs:
        try:
            os.remove(doc["caminho_arquivo"])
        except OSError:
            pass

    db.execute("DELETE FROM documentos WHERE funcionario_id = ?", (employee_id,))
    db.execute("DELETE FROM funcionarios WHERE id = ?", (employee_id,))
    db.commit()
    flash("Funcionário excluído com sucesso.", "info")
    return redirect(url_for("employees"))


# ---------------------------
# Documentos
# ---------------------------
@app.route("/documentos")
@login_required
def documents():
    rows = get_db().execute(
        """
        SELECT d.*, f.nome AS funcionario_nome, u.nome AS usuario_nome
        FROM documentos d
        JOIN funcionarios f ON f.id = d.funcionario_id
        LEFT JOIN usuarios u ON u.id = d.enviado_por
        ORDER BY d.id DESC
        """
    ).fetchall()
    return render_template("documents.html", rows=rows)


@app.route("/funcionarios/<int:employee_id>/documentos", methods=["POST"])
@login_required
def document_upload(employee_id: int):
    db = get_db()
    employee = db.execute("SELECT * FROM funcionarios WHERE id = ?", (employee_id,)).fetchone()
    if employee is None:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("employees"))

    tipo_documento = request.form.get("tipo_documento", "Outros").strip() or "Outros"
    files = request.files.getlist("arquivos")

    if not files or files[0].filename == "":
        flash("Selecione pelo menos um arquivo.", "warning")
        return redirect(url_for("employee_detail", employee_id=employee_id))

    folder = UPLOAD_DIR / str(employee_id)
    folder.mkdir(parents=True, exist_ok=True)

    enviados = 0
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
            final_name = f"{timestamp}_{filename}"
            path = folder / final_name
            file.save(path)
            db.execute(
                """
                INSERT INTO documentos (funcionario_id, tipo_documento, nome_arquivo, caminho_arquivo, enviado_por)
                VALUES (?, ?, ?, ?, ?)
                """,
                (employee_id, tipo_documento, final_name, str(path), session["user_id"]),
            )
            enviados += 1

    db.commit()
    flash(f"{enviados} documento(s) enviado(s) com sucesso.", "success")
    return redirect(url_for("employee_detail", employee_id=employee_id))


@app.route("/documentos/<int:doc_id>/baixar")
@login_required
def document_download(doc_id: int):
    doc = get_db().execute("SELECT * FROM documentos WHERE id = ?", (doc_id,)).fetchone()
    if doc is None or not Path(doc["caminho_arquivo"]).exists():
        flash("Arquivo não encontrado.", "danger")
        return redirect(url_for("documents"))
    return send_file(doc["caminho_arquivo"], as_attachment=True, download_name=doc["nome_arquivo"])


@app.route("/documentos/<int:doc_id>/excluir", methods=["POST"])
@login_required
def document_delete(doc_id: int):
    db = get_db()
    doc = db.execute("SELECT * FROM documentos WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:
        flash("Documento não encontrado.", "danger")
        return redirect(url_for("documents"))

    employee_id = doc["funcionario_id"]
    try:
        os.remove(doc["caminho_arquivo"])
    except OSError:
        pass
    db.execute("DELETE FROM documentos WHERE id = ?", (doc_id,))
    db.commit()
    flash("Documento excluído com sucesso.", "info")
    return redirect(url_for("employee_detail", employee_id=employee_id))


# ---------------------------
# Usuários
# ---------------------------
@app.route("/usuarios")
@login_required
@admin_required
def users():
    rows = get_db().execute("SELECT * FROM usuarios ORDER BY nome ASC").fetchall()
    return render_template("users.html", rows=rows)


@app.route("/usuarios/novo", methods=["POST"])
@login_required
@admin_required
def user_create():
    nome = request.form.get("nome", "").strip()
    usuario = request.form.get("usuario", "").strip()
    senha = request.form.get("senha", "")
    perfil = request.form.get("perfil", "rh")
    ativo = 1 if request.form.get("ativo") == "1" else 0

    if not nome or not usuario or not senha:
        flash("Preencha nome, usuário e senha.", "warning")
        return redirect(url_for("users"))

    if perfil not in PROFILE_OPTIONS:
        perfil = "rh"

    try:
        db = get_db()
        db.execute(
            """
            INSERT INTO usuarios (nome, usuario, senha_hash, perfil, ativo)
            VALUES (?, ?, ?, ?, ?)
            """,
            (nome, usuario, generate_password_hash(senha), perfil, ativo),
        )
        db.commit()
        flash("Usuário cadastrado com sucesso.", "success")
    except sqlite3.IntegrityError:
        flash("Já existe um usuário com esse login.", "danger")

    return redirect(url_for("users"))


@app.route("/usuarios/<int:user_id>/status", methods=["POST"])
@login_required
@admin_required
def user_toggle_status(user_id: int):
    db = get_db()
    user = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("users"))

    if user["usuario"] == "admin" and user["ativo"] == 1:
        flash("O usuário admin padrão não pode ser desativado.", "warning")
        return redirect(url_for("users"))

    novo_status = 0 if user["ativo"] == 1 else 1
    db.execute("UPDATE usuarios SET ativo = ? WHERE id = ?", (novo_status, user_id))
    db.commit()
    flash("Status do usuário atualizado.", "info")
    return redirect(url_for("users"))


@app.route("/usuarios/<int:user_id>/resetar-senha", methods=["POST"])
@login_required
@admin_required
def user_reset_password(user_id: int):
    db = get_db()
    user = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("Usuário não encontrado.", "danger")
        return redirect(url_for("users"))

    db.execute(
        "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
        (generate_password_hash("123456"), user_id),
    )
    db.commit()
    flash(f"Senha do usuário {user['usuario']} resetada para 123456.", "success")
    return redirect(url_for("users"))


# ---------------------------
# PDF
# ---------------------------
@app.route("/funcionarios/<int:employee_id>/ficha.pdf")
@login_required
def employee_pdf(employee_id: int):
    item = get_db().execute("SELECT * FROM funcionarios WHERE id = ?", (employee_id,)).fetchone()
    if item is None:
        flash("Funcionário não encontrado.", "danger")
        return redirect(url_for("employees"))

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "Ficha de Funcionário - Sistema RH")
    y -= 35

    pdf.setFont("Helvetica", 11)
    lines = [
        f"ID: {item['id']}",
        f"Nome: {item['nome']}",
        f"Cargo: {item['cargo'] or ''}",
        f"CPF: {item['cpf'] or ''}",
        f"Data de admissão: {item['data_admissao'] or ''}",
        f"Telefone: {item['telefone'] or ''}",
        f"E-mail: {item['email'] or ''}",
        f"Status: {item['status']}",
        f"Centro de custo: {item['centro_custo'] or ''}",
        f"Carteira assinada: {'Sim' if item['possui_carteira'] else 'Não'}",
        f"Salário: {format_currency(item['salario'])}",
        f"Observações: {item['observacoes'] or ''}",
        f"Emitido em: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
    ]
    for line in lines:
        pdf.drawString(50, y, line)
        y -= 22
        if y < 60:
            pdf.showPage()
            pdf.setFont("Helvetica", 11)
            y = height - 50

    pdf.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"funcionario_{employee_id}.pdf", mimetype="application/pdf")


def _employee_form_data(req) -> tuple:
    nome = req.form.get("nome", "").strip()
    cargo = req.form.get("cargo", "").strip()
    cpf = req.form.get("cpf", "").strip()
    data_admissao = req.form.get("data_admissao", "").strip() or None
    telefone = req.form.get("telefone", "").strip()
    email = req.form.get("email", "").strip()
    status = req.form.get("status", "Ativo").strip()
    centro_custo = req.form.get("centro_custo", "").strip()
    possui_carteira = 1 if req.form.get("possui_carteira") == "1" else 0
    salario = parse_currency(req.form.get("salario"))
    observacoes = req.form.get("observacoes", "").strip()

    if not nome:
        raise ValueError("Nome é obrigatório.")

    if status not in STATUS_OPTIONS:
        status = "Ativo"

    return (
        nome,
        cargo,
        cpf or None,
        data_admissao,
        telefone,
        email,
        status,
        centro_custo,
        possui_carteira,
        salario,
        observacoes,
    )


@app.errorhandler(ValueError)
def handle_value_error(err):
    flash(str(err), "warning")
    return redirect(request.referrer or url_for("dashboard"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)