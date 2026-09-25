import base64
import calendar
import csv
from datetime import date, datetime
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import time
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Conexão com Turso ou SQLite local
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
SECRET_KEY = os.environ.get("SECRET_KEY", "finance-secret-key-change-in-production-123").encode("utf-8")

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
public_path = os.path.join(root_dir, "public")

if os.environ.get("VERCEL"):
    UPLOAD_DIR = "/tmp/uploads"
else:
    UPLOAD_DIR = os.path.join(root_dir, "uploads")

os.makedirs(UPLOAD_DIR, exist_ok=True)

if TURSO_DATABASE_URL and TURSO_AUTH_TOKEN:
    try:
        import libsql_experimental as sqlite3
        DB_NAME = None
        def get_db():
            conn = sqlite3.connect(
                database=TURSO_DATABASE_URL,
                auth_token=TURSO_AUTH_TOKEN,
                autocommit=True
            )
            conn.row_factory = sqlite3.Row
            return conn
    except ImportError:
        import sqlite3
        DB_NAME = os.path.join(root_dir, "finance.db")
        def get_db():
            conn = sqlite3.connect(DB_NAME)
            conn.row_factory = sqlite3.Row
            return conn
else:
    import sqlite3
    DB_NAME = os.path.join(root_dir, "finance.db")
    def get_db():
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn

app = FastAPI(title="Painel Financeiro Pessoal")

# --- SEGURANÇA E AUTENTICAÇÃO ---
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 260000)
    return "pbkdf2:sha256:260000$" + salt + "$" + key.hex()

def verify_password(password: str, hashed: str) -> bool:
    try:
        parts = hashed.split("$")
        method_info = parts[0].split(":")
        subalgo = method_info[1]
        iters = int(method_info[2])
        salt = parts[1]
        orig_key = parts[2]
        verify_key = hashlib.pbkdf2_hmac(subalgo, password.encode("utf-8"), salt.encode("utf-8"), iters)
        return secrets.compare_digest(verify_key.hex(), orig_key)
    except Exception:
        return False

def create_token(user_id: int, email: str, name: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "name": name,
        "exp": int(time.time()) + (30 * 86400)  # 30 dias de validade
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return f"{payload_b64}.{sig_b64}"

def decode_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        expected_sig = hmac.new(SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "=" * ((4 - len(sig_b64) % 4) % 4))
        if not secrets.compare_digest(expected_sig, actual_sig):
            return None
        raw_payload = base64.urlsafe_b64decode(payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4))
        payload = json.loads(raw_payload.decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def get_current_user(
    authorization: Optional[str] = Header(None),
    token: Optional[str] = Query(None)
) -> dict:
    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization.split(" ", 1)[1].strip()
    elif token:
        auth_token = token.strip()

    if not auth_token:
        raise HTTPException(status_code=401, detail="Sessão não autenticada")

    payload = decode_token(auth_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")

    with get_db() as conn:
        user = conn.execute("SELECT id, email, name FROM users WHERE id = ?", (payload["user_id"],)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        return dict(user)

def init_db():
    with get_db() as conn:
        # Tabela de Usuários
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tabela de Contas
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1 REFERENCES users(id),
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                amount REAL NOT NULL,
                amount_paid REAL,
                due_date DATE NOT NULL,
                current_installment INTEGER,
                total_installments INTEGER,
                is_recurring BOOLEAN DEFAULT 0,
                payment_code TEXT,
                account TEXT DEFAULT 'Geral',
                receipt_path TEXT,
                status TEXT DEFAULT 'PENDING',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tabela de Receitas
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1 REFERENCES users(id),
                title TEXT NOT NULL,
                amount REAL NOT NULL,
                receive_date DATE NOT NULL,
                is_recurring BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Caixinhas de Reserva
        conn.execute("""
            CREATE TABLE IF NOT EXISTS saving_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1 REFERENCES users(id),
                name TEXT NOT NULL,
                target_amount REAL NOT NULL,
                current_amount REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tabela de Tetos por Categoria
        conn.execute("""
            CREATE TABLE IF NOT EXISTS category_budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1 REFERENCES users(id),
                category TEXT NOT NULL,
                budget_limit REAL NOT NULL,
                UNIQUE(user_id, category)
            )
        """)

        # Migração segura para colunas novas
        for table, col_def in [
            ("bills", "user_id INTEGER DEFAULT 1"),
            ("bills", "amount_paid REAL"),
            ("bills", "account TEXT DEFAULT 'Geral'"),
            ("bills", "receipt_path TEXT"),
            ("incomes", "user_id INTEGER DEFAULT 1"),
            ("saving_goals", "user_id INTEGER DEFAULT 1"),
            ("category_budgets", "user_id INTEGER DEFAULT 1")
        ]:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
            except Exception:
                pass

        # Garante usuário padrão inicial (admin) se a tabela de usuários estiver vazia
        try:
            existing = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
            if not existing:
                default_hash = hash_password("admin123")
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, name) VALUES (1, ?, ?, ?)",
                    ("admin@financeiro.com", default_hash, "Administrador")
                )
        except Exception:
            pass

        try:
            conn.commit()
        except Exception:
            pass

init_db()

# Modelos
class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class BillCreate(BaseModel):
    title: str
    category: str
    amount: float
    due_date: str
    account: Optional[str] = "Geral"
    current_installment: Optional[int] = 1
    total_installments: Optional[int] = 1
    is_recurring: Optional[bool] = False
    payment_code: Optional[str] = None

class BillUpdate(BaseModel):
    title: str
    category: str
    amount: float
    due_date: str
    account: Optional[str] = "Geral"
    payment_code: Optional[str] = None

class IncomeCreate(BaseModel):
    title: str
    amount: float
    receive_date: str
    is_recurring: Optional[bool] = False

class BudgetSet(BaseModel):
    category: str
    budget_limit: float

class GoalCreate(BaseModel):
    name: str
    target_amount: float
    current_amount: Optional[float] = 0.0

class GoalDeposit(BaseModel):
    amount: float

def add_months_safe(orig_date: date, months_to_add: int) -> date:
    year = orig_date.year + (orig_date.month + months_to_add - 1) // 12
    month = (orig_date.month + months_to_add - 1) % 12 + 1
    max_day = calendar.monthrange(year, month)[1]
    day = min(orig_date.day, max_day)
    return date(year, month, day)

# --- ROTAS DE AUTENTICAÇÃO ---
@app.post("/api/auth/register")
def register(data: UserRegister):
    email = data.email.strip().lower()
    name = data.name.strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="E-mail inválido")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="Senha deve ter no mínimo 4 caracteres")
    if not name:
        raise HTTPException(status_code=400, detail="Nome é obrigatório")

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="E-mail já cadastrado")

        pwd_hash = hash_password(data.password)
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
            (email, pwd_hash, name)
        )
        user_id = cursor.lastrowid
        try:
            conn.commit()
        except Exception:
            pass

        token = create_token(user_id, email, name)
        return {
            "token": token,
            "user": {"id": user_id, "name": name, "email": email},
            "message": "Conta criada com sucesso!"
        }

@app.post("/api/auth/login")
def login(data: UserLogin):
    email = data.email.strip().lower()
    with get_db() as conn:
        user = conn.execute("SELECT id, email, password_hash, name FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")

        token = create_token(user["id"], user["email"], user["name"])
        return {
            "token": token,
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]},
            "message": "Login realizado com sucesso!"
        }

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# --- ROTAS DE DESPESAS ---
@app.get("/api/bills")
def list_bills(month: Optional[int] = None, year: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        if month and year:
            prefix = f"{year:04d}-{month:02d}%"
            rows = conn.execute(
                "SELECT * FROM bills WHERE user_id = ? AND due_date LIKE ? ORDER BY due_date ASC",
                (current_user["id"], prefix)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM bills WHERE user_id = ? ORDER BY due_date ASC",
                (current_user["id"],)
            ).fetchall()
        return [dict(row) for row in rows]

@app.post("/api/bills")
def add_bill(bill: BillCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        start_date = datetime.strptime(bill.due_date, "%Y-%m-%d").date()
        total_inst = bill.total_installments or 1
        account_val = bill.account or "Geral"

        if total_inst > 1:
            records = []
            for i in range(total_inst):
                due = add_months_safe(start_date, i)
                records.append((
                    current_user["id"], bill.title, bill.category, bill.amount, due.isoformat(),
                    i + 1, total_inst, 0, bill.payment_code, account_val, "PENDING"
                ))
            conn.executemany("""
                INSERT INTO bills (user_id, title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
        else:
            conn.execute("""
                INSERT INTO bills (user_id, title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, status)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, 'PENDING')
            """, (current_user["id"], bill.title, bill.category, bill.amount, bill.due_date, 1 if bill.is_recurring else 0, bill.payment_code, account_val))

        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Despesa cadastrada com sucesso"}

@app.put("/api/bills/{bill_id}")
def update_bill(bill_id: int, bill: BillUpdate, cascade: bool = Query(False), current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        current = conn.execute("SELECT * FROM bills WHERE id = ? AND user_id = ?", (bill_id, current_user["id"])).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        if cascade and current["total_installments"] and current["total_installments"] > 1:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, account = ?, payment_code = ?
                WHERE user_id = ? AND title = ? AND total_installments = ? AND current_installment >= ?
            """, (bill.title, bill.category, bill.amount, bill.account or "Geral", bill.payment_code,
                  current_user["id"], current["title"], current["total_installments"], current["current_installment"]))
            conn.execute("UPDATE bills SET due_date = ? WHERE id = ? AND user_id = ?", (bill.due_date, bill_id, current_user["id"]))
        else:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, due_date = ?, account = ?, payment_code = ?
                WHERE id = ? AND user_id = ?
            """, (bill.title, bill.category, bill.amount, bill.due_date, bill.account or "Geral", bill.payment_code, bill_id, current_user["id"]))

        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Conta atualizada"}

@app.delete("/api/bills/{bill_id}")
def delete_bill(bill_id: int, cascade: bool = Query(False), current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        current = conn.execute("SELECT * FROM bills WHERE id = ? AND user_id = ?", (bill_id, current_user["id"])).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        if current["receipt_path"] and os.path.exists(current["receipt_path"]):
            try:
                os.remove(current["receipt_path"])
            except OSError:
                pass

        if cascade and current["total_installments"] and current["total_installments"] > 1:
            conn.execute("""
                DELETE FROM bills
                WHERE user_id = ? AND title = ? AND total_installments = ? AND current_installment >= ?
            """, (current_user["id"], current["title"], current["total_installments"], current["current_installment"]))
        else:
            conn.execute("DELETE FROM bills WHERE id = ? AND user_id = ?", (bill_id, current_user["id"]))

        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Removido com sucesso"}

# Pagamento e Upload de Comprovante
@app.post("/api/bills/{bill_id}/pay-upload")
async def pay_and_upload(
    bill_id: int,
    amount_paid: Optional[float] = Form(None),
    receipt: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM bills WHERE id = ? AND user_id = ?", (bill_id, current_user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        actual_paid = amount_paid if amount_paid is not None else row["amount"]
        receipt_path = row["receipt_path"]

        if receipt and receipt.filename:
            ext = os.path.splitext(receipt.filename)[1]
            saved_filename = f"receipt_{current_user['id']}_{bill_id}_{int(datetime.now().timestamp())}{ext}"
            file_location = os.path.join(UPLOAD_DIR, saved_filename)
            with open(file_location, "wb+") as f:
                shutil.copyfileobj(receipt.file, f)
            receipt_path = file_location

        conn.execute("""
            UPDATE bills
            SET status = 'PAID', amount_paid = ?, receipt_path = ?
            WHERE id = ? AND user_id = ?
        """, (actual_paid, receipt_path, bill_id, current_user["id"]))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Pagamento confirmado com sucesso", "status": "PAID", "receipt_path": receipt_path}

@app.patch("/api/bills/{bill_id}/unpay")
def unpay_bill(bill_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("UPDATE bills SET status = 'PENDING', amount_paid = NULL WHERE id = ? AND user_id = ?", (bill_id, current_user["id"]))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Pagamento desfeito"}

@app.get("/api/bills/{bill_id}/receipt")
def get_receipt(bill_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        row = conn.execute("SELECT receipt_path FROM bills WHERE id = ? AND user_id = ?", (bill_id, current_user["id"])).fetchone()
        if not row or not row["receipt_path"] or not os.path.exists(row["receipt_path"]):
            raise HTTPException(status_code=404, detail="Comprovante não encontrado")
        return FileResponse(row["receipt_path"])

@app.post("/api/bills/copy-recurring")
def copy_recurring(month: int, year: int, current_user: dict = Depends(get_current_user)):
    prev_month = 12 if month == 1 else month - 1
    prev_year = year - 1 if month == 1 else year
    prev_prefix = f"{prev_year:04d}-{prev_month:02d}%"

    with get_db() as conn:
        recurring = conn.execute(
            "SELECT title, category, amount, due_date, payment_code, account FROM bills WHERE user_id = ? AND is_recurring = 1 AND due_date LIKE ?",
            (current_user["id"], prev_prefix)
        ).fetchall()

        count = 0
        for b in recurring:
            orig_day = int(b["due_date"].split("-")[2])
            max_day = calendar.monthrange(year, month)[1]
            day = min(orig_day, max_day)
            new_due_date = f"{year:04d}-{month:02d}-{day:02d}"

            exists = conn.execute(
                "SELECT id FROM bills WHERE user_id = ? AND title = ? AND due_date = ?",
                (current_user["id"], b["title"], new_due_date)
            ).fetchone()
            if not exists:
                conn.execute("""
                    INSERT INTO bills (user_id, title, category, amount, due_date, is_recurring, payment_code, account, status)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, 'PENDING')
                """, (current_user["id"], b["title"], b["category"], b["amount"], new_due_date, b["payment_code"], b["account"]))
                count += 1

        try:
            conn.commit()
        except Exception:
            pass
        return {"message": f"{count} conta(s) recorrente(s) importada(s)."}

# --- RECEITAS ---
@app.get("/api/incomes")
def list_incomes(month: int, year: int, current_user: dict = Depends(get_current_user)):
    prefix = f"{year:04d}-{month:02d}%"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM incomes WHERE user_id = ? AND receive_date LIKE ? ORDER BY receive_date ASC",
            (current_user["id"], prefix)
        ).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/incomes")
def add_income(income: IncomeCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO incomes (user_id, title, amount, receive_date, is_recurring)
            VALUES (?, ?, ?, ?, ?)
        """, (current_user["id"], income.title, income.amount, income.receive_date, 1 if income.is_recurring else 0))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Receita registrada"}

@app.delete("/api/incomes/{income_id}")
def delete_income(income_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("DELETE FROM incomes WHERE id = ? AND user_id = ?", (income_id, current_user["id"]))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Receita excluída"}

# --- CAIXINHAS / METAS DE RESERVA ---
@app.get("/api/goals")
def list_goals(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM saving_goals WHERE user_id = ? ORDER BY id ASC",
            (current_user["id"],)
        ).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/goals")
def create_goal(goal: GoalCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO saving_goals (user_id, name, target_amount, current_amount)
            VALUES (?, ?, ?, ?)
        """, (current_user["id"], goal.name, goal.target_amount, goal.current_amount or 0.0))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Meta criada com sucesso"}

@app.post("/api/goals/{goal_id}/deposit")
def deposit_goal(goal_id: int, dep: GoalDeposit, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("""
            UPDATE saving_goals
            SET current_amount = MAX(0, current_amount + ?)
            WHERE id = ? AND user_id = ?
        """, (dep.amount, goal_id, current_user["id"]))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Saldo da caixinha atualizado"}

@app.delete("/api/goals/{goal_id}")
def delete_goal(goal_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("DELETE FROM saving_goals WHERE id = ? AND user_id = ?", (goal_id, current_user["id"]))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Meta removida"}

# --- TETOS, PROJEÇÃO E MATRIZ ANUAL ---
@app.get("/api/budgets")
def get_budgets(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT category, budget_limit FROM category_budgets WHERE user_id = ?",
            (current_user["id"],)
        ).fetchall()
        return {r["category"]: r["budget_limit"] for r in rows}

@app.post("/api/budgets")
def set_budget(budget: BudgetSet, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO category_budgets (user_id, category, budget_limit)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, category) DO UPDATE SET budget_limit = excluded.budget_limit
        """, (current_user["id"], budget.category, budget.budget_limit))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Teto configurado"}

@app.get("/api/dashboard/annual")
def get_annual_matrix(year: int, current_user: dict = Depends(get_current_user)):
    month_names = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    result = []
    with get_db() as conn:
        for m in range(1, 13):
            prefix = f"{year:04d}-{m:02d}%"
            exp_row = conn.execute(
                "SELECT SUM(COALESCE(amount_paid, amount)) as total FROM bills WHERE user_id = ? AND due_date LIKE ?",
                (current_user["id"], prefix)
            ).fetchone()
            expenses = exp_row["total"] or 0.0

            inc_row = conn.execute(
                "SELECT SUM(amount) as total FROM incomes WHERE user_id = ? AND receive_date LIKE ?",
                (current_user["id"], prefix)
            ).fetchone()
            incomes = inc_row["total"] or 0.0

            result.append({
                "month_num": m,
                "month_name": month_names[m - 1],
                "income": incomes,
                "expense": expenses,
                "balance": incomes - expenses
            })
    return result

@app.get("/api/dashboard/projection")
def get_projection(start_month: int, start_year: int, current_user: dict = Depends(get_current_user)):
    results = []
    curr_date = date(start_year, start_month, 1)
    with get_db() as conn:
        for i in range(6):
            m_date = add_months_safe(curr_date, i)
            prefix = f"{m_date.year:04d}-{m_date.month:02d}%"
            row = conn.execute(
                "SELECT SUM(COALESCE(amount_paid, amount)) as total FROM bills WHERE user_id = ? AND due_date LIKE ?",
                (current_user["id"], prefix)
            ).fetchone()
            total = row["total"] or 0.0
            month_names = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
            label = f"{month_names[m_date.month - 1]}/{str(m_date.year)[2:]}"
            results.append({"month_label": label, "total": total})
    return results

@app.get("/api/export/csv")
def export_csv(month: int, year: int, current_user: dict = Depends(get_current_user)):
    prefix = f"{year:04d}-{month:02d}%"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM bills WHERE user_id = ? AND due_date LIKE ? ORDER BY due_date ASC",
            (current_user["id"], prefix)
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(["ID", "Título", "Categoria", "Conta/Banco", "Valor Previsto", "Valor Pago", "Vencimento", "Parcela", "Status", "Código Pix/Boleto"])

    for r in rows:
        inst = f"{r['current_installment']}/{r['total_installments']}" if r['total_installments'] and r['total_installments'] > 1 else ("Fixa" if r['is_recurring'] else "Avulsa")
        writer.writerow([
            r["id"], r["title"], r["category"], r["account"] or "Geral",
            f"{r['amount']:.2f}".replace('.', ','),
            f"{r['amount_paid']:.2f}".replace('.', ',') if r['amount_paid'] is not None else "",
            r["due_date"], inst, "Pago" if r["status"] == "PAID" else "Pendente", r["payment_code"] or ""
        ])

    csv_data = output.getvalue().encode('utf-8-sig')
    headers = {"Content-Disposition": f"attachment; filename=contas_{year:04d}_{month:02d}.csv"}
    return Response(content=csv_data, media_type="text/csv; charset=utf-8", headers=headers)

@app.get("/api/backup")
def download_backup(current_user: dict = Depends(get_current_user)):
    if not DB_NAME or not os.path.exists(DB_NAME):
        raise HTTPException(status_code=400, detail="Backup SQLite direto disponível apenas em modo local.")
    return FileResponse(DB_NAME, media_type="application/x-sqlite3", filename=f"finance_backup_{date.today().isoformat()}.db")

@app.get("/manifest.json")
def pwa_manifest():
    content = """{
      "name": "Finanças Pessoais",
      "short_name": "Finanças",
      "start_url": "/",
      "display": "standalone",
      "background_color": "#020617",
      "theme_color": "#020617",
      "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/2454/2454269.png", "sizes": "512x512", "type": "image/png"}]
    }"""
    return Response(content=content, media_type="application/json")

@app.get("/sw.js")
def service_worker():
    content = """
    const CACHE_NAME = 'financas-v1';
    self.addEventListener('install', (e) => {
        self.skipWaiting();
    });
    self.addEventListener('fetch', (e) => {
        e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    });
    """
    return Response(content=content, media_type="application/javascript")

# Rota raiz servindo o index.html na raiz do projeto
@app.get("/")
def serve_index():
    for p in [
        os.path.join(root_dir, "index.html"),
        "index.html",
        os.path.join(public_path, "index.html"),
        "public/index.html"
    ]:
        if os.path.exists(p):
            return FileResponse(p)
    return {"message": "API online. Coloque o index.html na raiz."}
