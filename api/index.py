import base64
import calendar
import csv
from datetime import date, datetime, timedelta
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import time
import urllib.error
import urllib.request
from typing import Optional

import jwt
from ofxparse import OfxParser
from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

SECRET_KEY = os.environ.get("JWT_SECRET", os.environ.get("SECRET_KEY", "super-secret-finance-key-123456"))
ALGORITHM = "HS256"
DEFAULT_TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CRON_SECRET = os.environ.get("CRON_SECRET", "cron-secret-padrao-123")

# No Render ou localmente, guardamos a base de dados na raiz do projeto; na Vercel em /tmp
IS_VERCEL = os.environ.get("VERCEL") == "1" or "VERCEL" in os.environ
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
root_dir = BASE_DIR
public_path = os.path.join(root_dir, "public")

DB_DIR = "/tmp" if IS_VERCEL else BASE_DIR
DB_PATH = os.path.join(DB_DIR, "finance.db")
DB_NAME = DB_PATH
UPLOAD_DIR = os.path.join(DB_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Conexão com Turso ou SQLite local
TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")

app = FastAPI(title="Painel Financeiro Pessoal")

# Habilita CORS para evitar bloqueios de requisições no navegador
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if TURSO_DATABASE_URL and TURSO_AUTH_TOKEN:
    try:
        import libsql_experimental as sqlite3
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
        def get_db():
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            return conn
else:
    import sqlite3
    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

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
        "sub": str(user_id),
        "user_id": user_id,
        "id": user_id,
        "email": email,
        "name": name,
        "exp": int(time.time()) + (30 * 86400)  # 30 dias de validade
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "HS256"])
    except Exception:
        return None

class User(BaseModel):
    id: int
    email: str
    name: str

    def __getitem__(self, item):
        return getattr(self, item)

def get_current_user(
    authorization: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
    access_token: Optional[str] = Query(None),
    x_token: Optional[str] = Header(None, alias="x-token"),
    x_access_token: Optional[str] = Header(None, alias="x-access-token"),
    auth_token_cookie: Optional[str] = Cookie(None, alias="auth_token")
) -> User:
    auth_token = None
    if isinstance(authorization, str) and authorization.strip():
        if authorization.lower().startswith("bearer "):
            auth_token = authorization.split(" ", 1)[1].strip()
        else:
            auth_token = authorization.strip()
    elif isinstance(token, str) and token.strip():
        auth_token = token.strip()
    elif isinstance(access_token, str) and access_token.strip():
        auth_token = access_token.strip()
    elif isinstance(x_token, str) and x_token.strip():
        auth_token = x_token.strip()
    elif isinstance(x_access_token, str) and x_access_token.strip():
        auth_token = x_access_token.strip()
    elif isinstance(auth_token_cookie, str) and auth_token_cookie.strip():
        auth_token = auth_token_cookie.strip()

    if not auth_token:
        raise HTTPException(status_code=401, detail="Sessão não autenticada")

    payload = decode_token(auth_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")

    uid = payload.get("user_id") or payload.get("id") or payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Token sem identificador de usuário")

    with get_db() as conn:
        user = conn.execute("SELECT id, email, name FROM users WHERE id = ?", (int(uid),)).fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        return User(id=user["id"], email=user["email"], name=user["name"])

def init_db():
    try:
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

            # Tabela de Cartões de Crédito
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credit_cards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER DEFAULT 1 REFERENCES users(id),
                    name TEXT NOT NULL,
                    limit_amount REAL NOT NULL,
                    closing_day INTEGER NOT NULL,
                    due_day INTEGER NOT NULL,
                    color TEXT DEFAULT '#6366f1',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Migração segura para colunas novas
            for table, col_def in [
                ("bills", "user_id INTEGER DEFAULT 1"),
                ("bills", "amount_paid REAL"),
                ("bills", "account TEXT DEFAULT 'Geral'"),
                ("bills", "receipt_path TEXT"),
                ("bills", "card_id INTEGER"),
                ("bills", "installment_group_id TEXT"),
                ("incomes", "user_id INTEGER DEFAULT 1"),
                ("saving_goals", "user_id INTEGER DEFAULT 1"),
                ("category_budgets", "user_id INTEGER DEFAULT 1"),
                ("users", "telegram_chat_id TEXT"),
                ("users", "telegram_bot_token TEXT"),
                ("users", "telegram_notifications_enabled INTEGER DEFAULT 0"),
                ("credit_cards", "user_id INTEGER DEFAULT 1")
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
    except Exception as e:
        print(f"Erro ao inicializar base de dados: {e}")

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/api/health")
def health():
    return {"status": "ok", "db_path": DB_PATH}

# Modelos
class UserRegister(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class UserLogin(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str

class BillCreate(BaseModel):
    title: str
    category: str
    amount: float
    due_date: str
    account: Optional[str] = "Geral"
    card_id: Optional[int] = None
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
    card_id: Optional[int] = None
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

class CreditCardCreate(BaseModel):
    name: str
    limit_amount: Optional[float] = 0.0
    card_limit: Optional[float] = 0.0
    closing_day: int
    due_day: int
    color: Optional[str] = "#6366f1"

class CreditCardUpdate(BaseModel):
    name: str
    limit_amount: Optional[float] = 0.0
    card_limit: Optional[float] = 0.0
    closing_day: int
    due_day: int
    color: Optional[str] = "#6366f1"

class CalculateDueRequest(BaseModel):
    card_id: int
    purchase_date: str

class TelegramConfig(BaseModel):
    chat_id: Optional[str] = None
    bot_token: Optional[str] = None
    enabled: Optional[bool] = True

def add_months_safe(orig_date: date, months_to_add: int) -> date:
    year = orig_date.year + (orig_date.month + months_to_add - 1) // 12
    month = (orig_date.month + months_to_add - 1) % 12 + 1
    max_day = calendar.monthrange(year, month)[1]
    day = min(orig_date.day, max_day)
    return date(year, month, day)

def normalize_date_str(val: str) -> str:
    val = val.strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%d/%m/%y"):
        try:
            return datetime.strptime(val, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return date.today().strftime("%Y-%m-%d")

# --- ROTAS DE AUTENTICAÇÃO ---
@app.post("/api/auth/register")
@app.post("/api/register")
@app.post("/api/user/register")
def register(data: UserRegister):
    email = (data.email or data.username or "").strip().lower()
    name = (data.name or data.username or (email.split("@")[0] if "@" in email else "")).strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="E-mail inválido")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="Senha deve ter no mínimo 4 caracteres")
    if not name:
        name = email.split("@")[0].capitalize()

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
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": user_id, "name": name, "email": email},
            "message": "Conta criada com sucesso!"
        }

@app.post("/api/auth/login")
@app.post("/api/login")
def login(data: UserLogin):
    email = (data.email or data.username or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="E-mail ou nome de usuário é obrigatório")
    with get_db() as conn:
        user = conn.execute("SELECT id, email, password_hash, name FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")

        token = create_token(user["id"], user["email"], user["name"])
        return {
            "token": token,
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]},
            "message": "Login realizado com sucesso!"
        }

@app.post("/api/auth/token")
@app.post("/api/token")
async def token_endpoint(request: Request):
    content_type = request.headers.get("content-type", "")
    username = ""
    password = ""
    if "application/json" in content_type:
        try:
            body = await request.json()
            username = body.get("username") or body.get("email") or ""
            password = body.get("password") or ""
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            username = form.get("username") or form.get("email") or ""
            password = form.get("password") or ""
        except Exception:
            pass

    email = username.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Credenciais incompletas")

    with get_db() as conn:
        user = conn.execute("SELECT id, email, password_hash, name FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")

        token = create_token(user["id"], user["email"], user["name"])
        return {
            "access_token": token,
            "token": token,
            "token_type": "bearer",
            "user": {"id": user["id"], "name": user["name"], "email": user["email"]}
        }

@app.get("/api/auth/me")
@app.get("/api/me")
@app.get("/api/user/me")
@app.get("/api/user")
def get_me(current_user: User = Depends(get_current_user)):
    user_dict = {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email
    }
    return {
        **user_dict,
        "user": user_dict
    }

@app.post("/api/auth/logout")
@app.post("/api/logout")
def logout():
    return {"message": "Sessão encerrada com sucesso"}

# Endpoint para auto-sugestão de categoria com base no histórico do usuário
@app.get("/api/bills/suggest-category")
def suggest_category(term: str = Query(...), user: User = Depends(get_current_user)):
    with get_db() as conn:
        row = conn.execute("""
            SELECT category, account 
            FROM bills 
            WHERE user_id = ? AND title LIKE ? 
            ORDER BY id DESC LIMIT 1
        """, (user.id, f"%{term.strip()}%")).fetchone()
        if row:
            return {"category": row["category"], "account": row["account"]}
        return {"category": None, "account": None}

# --- ROTAS DE DESPESAS ---
@app.get("/api/bills")
def list_bills(
    month: Optional[int] = None,
    year: Optional[int] = None,
    current_user: User = Depends(get_current_user)
):
    with get_db() as conn:
        # Impossível trazer dados de outra pessoa, pois o user_id vem do token autenticado
        if month and year:
            prefix = f"{year:04d}-{month:02d}%"
            rows = conn.execute(
                "SELECT * FROM bills WHERE user_id = ? AND due_date LIKE ? ORDER BY due_date ASC",
                (current_user.id, prefix)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM bills WHERE user_id = ? ORDER BY due_date ASC",
                (current_user.id,)
            ).fetchall()
        return [dict(row) for row in rows]

@app.post("/api/bills")
def add_bill(bill: BillCreate, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        start_date = datetime.strptime(bill.due_date, "%Y-%m-%d").date()
        total_inst = bill.total_installments or 1
        account_val = bill.account or "Geral"
        card_id_val = bill.card_id

        # Se selecionou um cartão e a conta for Geral, atribui o nome do cartão
        if card_id_val and account_val == "Geral":
            c_row = conn.execute("SELECT name FROM credit_cards WHERE id = ? AND user_id = ?", (card_id_val, current_user["id"])).fetchone()
            if c_row:
                account_val = f"Cartão {c_row['name']}"

        if total_inst > 1:
            records = []
            for i in range(total_inst):
                due = add_months_safe(start_date, i)
                records.append((
                    current_user["id"], bill.title, bill.category, bill.amount, due.isoformat(),
                    i + 1, total_inst, 0, bill.payment_code, account_val, card_id_val, "PENDING"
                ))
            conn.executemany("""
                INSERT INTO bills (user_id, title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, card_id, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
        else:
            conn.execute("""
                INSERT INTO bills (user_id, title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, card_id, status)
                VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, 'PENDING')
            """, (current_user["id"], bill.title, bill.category, bill.amount, bill.due_date, 1 if bill.is_recurring else 0, bill.payment_code, account_val, card_id_val))

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

        account_val = bill.account or "Geral"
        card_id_val = bill.card_id
        if card_id_val and account_val == "Geral":
            c_row = conn.execute("SELECT name FROM credit_cards WHERE id = ? AND user_id = ?", (card_id_val, current_user["id"])).fetchone()
            if c_row:
                account_val = f"Cartão {c_row['name']}"

        if cascade and current["total_installments"] and current["total_installments"] > 1:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, account = ?, card_id = ?, payment_code = ?
                WHERE user_id = ? AND title = ? AND total_installments = ? AND current_installment >= ?
            """, (bill.title, bill.category, bill.amount, account_val, card_id_val, bill.payment_code,
                  current_user["id"], current["title"], current["total_installments"], current["current_installment"]))
            conn.execute("UPDATE bills SET due_date = ? WHERE id = ? AND user_id = ?", (bill.due_date, bill_id, current_user["id"]))
        else:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, due_date = ?, account = ?, card_id = ?, payment_code = ?
                WHERE id = ? AND user_id = ?
            """, (bill.title, bill.category, bill.amount, bill.due_date, account_val, card_id_val, bill.payment_code, bill_id, current_user["id"]))

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

# Endpoint para upload e conversão em lote de extrato bancário OFX/CSV
@app.post("/api/import/statement")
async def import_statement(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    filename = file.filename.lower()
    imported_bills = 0
    imported_incomes = 0

    if filename.endswith(".ofx"):
        content = await file.read()
        ofx = OfxParser.parse(io.BytesIO(content))
        with get_db() as conn:
            for account in ofx.accounts:
                for tx in account.statement.transactions:
                    tx_date = tx.date.strftime("%Y-%m-%d")
                    tx_amount = float(tx.amount)
                    tx_memo = tx.memo or tx.payee or "Transação Bancária"

                    if tx_amount < 0:
                        # Tenta auto-sugerir categoria baseado no histórico
                        cat_row = conn.execute("""
                            SELECT category FROM bills 
                            WHERE user_id = ? AND title LIKE ? 
                            ORDER BY id DESC LIMIT 1
                        """, (user.id, f"%{tx_memo[:20].strip()}%")).fetchone()
                        cat = cat_row["category"] if cat_row else "Importado"

                        conn.execute("""
                            INSERT INTO bills (user_id, title, category, amount, due_date, account, status)
                            VALUES (?, ?, ?, ?, ?, 'Extrato OFX', 'PAID')
                        """, (user.id, tx_memo, cat, abs(tx_amount), tx_date))
                        imported_bills += 1
                    else:
                        conn.execute("""
                            INSERT INTO incomes (user_id, title, amount, receive_date)
                            VALUES (?, ?, ?, ?)
                        """, (user.id, tx_memo, tx_amount, tx_date))
                        imported_incomes += 1
            try:
                conn.commit()
            except Exception:
                pass

    elif filename.endswith(".csv"):
        content = await file.read()
        text = content.decode("utf-8-sig", errors="ignore")
        reader = csv.reader(io.StringIO(text), delimiter=';' if ';' in text else ',')
        header = next(reader, None)

        col_date_idx = 0
        col_desc_idx = 1
        col_amount_idx = 2

        if header:
            header_lower = [h.strip().lower() for h in header]
            for idx, h in enumerate(header_lower):
                if any(k in h for k in ("data", "date")):
                    col_date_idx = idx
                elif any(k in h for k in ("descri", "hist", "memo", "lança", "lanca", "identif", "título", "titulo")):
                    col_desc_idx = idx
                elif any(k in h for k in ("valor", "amount", "quantia", "total")):
                    col_amount_idx = idx

        with get_db() as conn:
            for row in reader:
                if not row or len(row) <= max(col_date_idx, col_desc_idx, col_amount_idx):
                    continue
                try:
                    tx_date = normalize_date_str(row[col_date_idx])
                    tx_memo = row[col_desc_idx].strip() or "Transação Bancária"
                    raw_val = row[col_amount_idx].replace("R$", "").replace(" ", "").strip()
                    if "," in raw_val and "." in raw_val:
                        raw_val = raw_val.replace(".", "").replace(",", ".")
                    elif "," in raw_val:
                        raw_val = raw_val.replace(",", ".")
                    tx_amount = float(raw_val)

                    if tx_amount < 0:
                        cat_row = conn.execute("""
                            SELECT category FROM bills 
                            WHERE user_id = ? AND title LIKE ? 
                            ORDER BY id DESC LIMIT 1
                        """, (user.id, f"%{tx_memo[:20].strip()}%")).fetchone()
                        cat = cat_row["category"] if cat_row else "Importado"

                        conn.execute("""
                            INSERT INTO bills (user_id, title, category, amount, due_date, account, status)
                            VALUES (?, ?, ?, ?, ?, 'Extrato CSV', 'PAID')
                        """, (user.id, tx_memo, cat, abs(tx_amount), tx_date))
                        imported_bills += 1
                    else:
                        conn.execute("""
                            INSERT INTO incomes (user_id, title, amount, receive_date)
                            VALUES (?, ?, ?, ?)
                        """, (user.id, tx_memo, tx_amount, tx_date))
                        imported_incomes += 1
                except Exception:
                    continue
            try:
                conn.commit()
            except Exception:
                pass
    else:
        raise HTTPException(status_code=400, detail="Formato não suportado. Envie um arquivo .ofx ou .csv.")

    return {
        "message": f"Sucesso! {imported_bills} despesas e {imported_incomes} receitas importadas do extrato."
    }

# --- ROTAS DE CARTÕES DE CRÉDITO ---
@app.get("/api/cards")
def list_cards(current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        cards = conn.execute(
            "SELECT * FROM credit_cards WHERE user_id = ? ORDER BY name ASC",
            (current_user.id,)
        ).fetchall()

        result = []
        for c in cards:
            card_dict = dict(c)
            row = conn.execute("""
                SELECT COALESCE(SUM(amount), 0.0) as used
                FROM bills
                WHERE user_id = ? AND (card_id = ? OR account = ?) AND status = 'PENDING'
            """, (current_user.id, c["id"], c["name"])).fetchone()

            used = float(row["used"]) if row else 0.0
            limit_total = float(c["limit_amount"])
            available = max(0.0, limit_total - used)
            pct_used = min(100.0, (used / limit_total * 100.0)) if limit_total > 0 else 0.0

            card_dict["used_amount"] = used
            card_dict["available_amount"] = available
            card_dict["used_percentage"] = round(pct_used, 1)
            card_dict["card_limit"] = limit_total
            result.append(card_dict)

        return result

@app.post("/api/cards")
def create_card(card: CreditCardCreate, current_user: User = Depends(get_current_user)):
    name = card.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Nome do cartão é obrigatório")
    limit_val = float(card.card_limit or card.limit_amount or 0.0)
    if limit_val <= 0:
        raise HTTPException(status_code=400, detail="Limite deve ser maior que zero")
    if not (1 <= card.closing_day <= 31) or not (1 <= card.due_day <= 31):
        raise HTTPException(status_code=400, detail="Dias de fechamento e vencimento devem ser entre 1 e 31")

    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO credit_cards (user_id, name, limit_amount, closing_day, due_day, color)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (current_user.id, name, limit_val, card.closing_day, card.due_day, card.color or "#6366f1"))
        card_id = cursor.lastrowid
        try:
            conn.commit()
        except Exception:
            pass
        return {"id": card_id, "message": "Cartão cadastrado com sucesso!"}

@app.put("/api/cards/{card_id}")
def update_card(card_id: int, card: CreditCardUpdate, current_user: User = Depends(get_current_user)):
    name = card.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Nome do cartão é obrigatório")
    limit_val = float(card.card_limit or card.limit_amount or 0.0)
    if limit_val <= 0:
        raise HTTPException(status_code=400, detail="Limite deve ser maior que zero")
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM credit_cards WHERE id = ? AND user_id = ?", (card_id, current_user.id)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Cartão não encontrado")
        conn.execute("""
            UPDATE credit_cards
            SET name = ?, limit_amount = ?, closing_day = ?, due_day = ?, color = ?
            WHERE id = ? AND user_id = ?
        """, (name, limit_val, card.closing_day, card.due_day, card.color or "#6366f1", card_id, current_user.id))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Cartão atualizado com sucesso!"}

@app.delete("/api/cards/{card_id}")
def delete_card(card_id: int, current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM credit_cards WHERE id = ? AND user_id = ?", (card_id, current_user.id)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Cartão não encontrado")
        conn.execute("DELETE FROM credit_cards WHERE id = ? AND user_id = ?", (card_id, current_user.id))
        conn.execute("UPDATE bills SET card_id = NULL WHERE card_id = ? AND user_id = ?", (card_id, current_user.id))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Cartão removido com sucesso!"}

@app.get("/api/cards/{card_id}/invoice")
def get_card_invoice(card_id: int, month: Optional[int] = None, year: Optional[int] = None, current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        card = conn.execute("SELECT * FROM credit_cards WHERE id = ? AND user_id = ?", (card_id, current_user.id)).fetchone()
        if not card:
            raise HTTPException(status_code=404, detail="Cartão não encontrado")

        query = "SELECT * FROM bills WHERE user_id = ? AND (card_id = ? OR account = ?)"
        params = [current_user.id, card_id, card["name"]]
        if month and year:
            prefix = f"{year:04d}-{month:02d}%"
            query += " AND due_date LIKE ?"
            params.append(prefix)
        query += " ORDER BY due_date ASC"

        items = conn.execute(query, params).fetchall()
        total = sum(float(i["amount"]) for i in items)
        pending_total = sum(float(i["amount"]) for i in items if i["status"] != "PAID")
        paid_total = sum(float(i["amount"]) for i in items if i["status"] == "PAID")

        return {
            "card": dict(card),
            "items": [dict(i) for i in items],
            "total": total,
            "pending_total": pending_total,
            "paid_total": paid_total
        }

@app.post("/api/cards/calculate-due")
def calculate_card_due(data: CalculateDueRequest, current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        card = conn.execute("SELECT * FROM credit_cards WHERE id = ? AND user_id = ?", (data.card_id, current_user.id)).fetchone()
        if not card:
            raise HTTPException(status_code=404, detail="Cartão não encontrado")

        try:
            p_date = datetime.strptime(data.purchase_date, "%Y-%m-%d").date()
        except Exception:
            p_date = date.today()

        closing_day = int(card["closing_day"])
        due_day = int(card["due_day"])

        if p_date.day <= closing_day:
            if due_day > closing_day:
                due_y = p_date.year
                due_m = p_date.month
            else:
                due_y = p_date.year + (p_date.month // 12)
                due_m = (p_date.month % 12) + 1
        else:
            if due_day > closing_day:
                due_y = p_date.year + (p_date.month // 12)
                due_m = (p_date.month % 12) + 1
            else:
                due_m_total = p_date.month + 1
                due_y = p_date.year + (due_m_total // 12)
                due_m = (due_m_total % 12) + 1

        max_day = calendar.monthrange(due_y, due_m)[1]
        final_day = min(due_day, max_day)
        calculated_due_date = f"{due_y:04d}-{due_m:02d}-{final_day:02d}"

        return {"calculated_due_date": calculated_due_date}

# --- ALERTA TELEGRAM ---
def send_telegram_msg(bot_token: str, chat_id: str, message: str) -> bool:
    if not bot_token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": str(chat_id).strip(),
        "text": message,
        "parse_mode": "Markdown"
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        return res_data.get("ok", False)

@app.get("/api/telegram/config")
@app.get("/api/notifications/settings")
def get_telegram_config(current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        user_row = conn.execute(
            "SELECT telegram_chat_id, telegram_bot_token, telegram_notifications_enabled FROM users WHERE id = ?",
            (current_user.id,)
        ).fetchone()

        has_token = bool(user_row and user_row["telegram_bot_token"]) or bool(DEFAULT_TELEGRAM_BOT_TOKEN)
        chat_id = user_row["telegram_chat_id"] if user_row else ""
        enabled = bool(user_row["telegram_notifications_enabled"]) if user_row else False

        return {
            "chat_id": chat_id or "",
            "has_token": has_token,
            "custom_token_configured": bool(user_row and user_row["telegram_bot_token"]),
            "enabled": enabled,
            "configured": bool(chat_id and has_token)
        }

@app.post("/api/telegram/config")
@app.post("/api/notifications/settings")
def save_telegram_config(cfg: TelegramConfig, current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        token_to_save = cfg.bot_token.strip() if cfg.bot_token else None
        chat_id_to_save = cfg.chat_id.strip() if cfg.chat_id else None
        enabled_val = 1 if cfg.enabled else 0

        if token_to_save:
            conn.execute("""
                UPDATE users 
                SET telegram_chat_id = ?, telegram_bot_token = ?, telegram_notifications_enabled = ?
                WHERE id = ?
            """, (chat_id_to_save, token_to_save, enabled_val, current_user.id))
        else:
            conn.execute("""
                UPDATE users 
                SET telegram_chat_id = ?, telegram_notifications_enabled = ?
                WHERE id = ?
            """, (chat_id_to_save, enabled_val, current_user.id))
        try:
            conn.commit()
        except Exception:
            pass
        return {"message": "Configurações do Telegram salvas com sucesso!"}

@app.post("/api/telegram/test")
@app.post("/api/notifications/test-telegram")
def test_telegram_alert(current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        user_row = conn.execute(
            "SELECT telegram_chat_id, telegram_bot_token, name FROM users WHERE id = ?",
            (current_user.id,)
        ).fetchone()
        if not user_row or not user_row["telegram_chat_id"]:
            raise HTTPException(status_code=400, detail="Chat ID do Telegram não configurado.")

        bot_token = user_row["telegram_bot_token"] or DEFAULT_TELEGRAM_BOT_TOKEN
        if not bot_token:
            raise HTTPException(status_code=400, detail="Token do Bot do Telegram não configurado. Informe o bot token da sua aplicação.")

        user_name = user_row["name"] or "Usuário"
        msg = (
            f"🚀 *Meu Financeiro - Teste de Notificação*\n\n"
            f"Olá, *{user_name}*! 👋\n"
            f"Sua integração com o Telegram está ativa e funcionando perfeitamente.\n"
            f"Você receberá alertas de contas e vencimentos."
        )

        try:
            success = send_telegram_msg(bot_token, user_row["telegram_chat_id"], msg)
            if success:
                return {"message": "Mensagem de teste enviada com sucesso no seu Telegram!"}
            else:
                raise HTTPException(status_code=502, detail="Telegram recusou a mensagem. Verifique se você já enviou /start para o bot.")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            raise HTTPException(status_code=400, detail=f"Erro na API do Telegram: {err_msg}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Falha ao enviar mensagem: {str(e)}")

@app.post("/api/telegram/send-digest")
@app.post("/api/notifications/send-alerts")
def send_telegram_digest(current_user: User = Depends(get_current_user)):
    with get_db() as conn:
        user_row = conn.execute(
            "SELECT telegram_chat_id, telegram_bot_token, name FROM users WHERE id = ?",
            (current_user.id,)
        ).fetchone()
        if not user_row or not user_row["telegram_chat_id"]:
            raise HTTPException(status_code=400, detail="Chat ID do Telegram não configurado.")

        bot_token = user_row["telegram_bot_token"] or DEFAULT_TELEGRAM_BOT_TOKEN
        if not bot_token:
            raise HTTPException(status_code=400, detail="Token do Bot do Telegram não configurado.")

        today_str = date.today().isoformat()
        in_3_days_str = (date.today() + timedelta(days=3)).isoformat()

        bills = conn.execute("""
            SELECT title, amount, due_date, account
            FROM bills
            WHERE user_id = ? AND status = 'PENDING'
            ORDER BY due_date ASC
        """, (current_user.id,)).fetchall()

        overdue = []
        today_bills = []
        upcoming = []
        total_pending = 0.0

        for b in bills:
            amt = float(b["amount"])
            total_pending += amt
            d_date = b["due_date"]
            if d_date < today_str:
                overdue.append(b)
            elif d_date == today_str:
                today_bills.append(b)
            elif d_date <= in_3_days_str:
                upcoming.append(b)

        user_name = user_row["name"] or "Usuário"
        lines = [f"📊 *Resumo Financeiro - {date.today().strftime('%d/%m/%Y')}*", f"Olá, *{user_name}*!\n"]

        if not bills:
            lines.append("🎉 *Parabéns! Você não tem nenhuma conta pendente.*")
        else:
            if overdue:
                lines.append(f"⚠️ *Em Atraso ({len(overdue)}):*")
                for b in overdue:
                    due_fmt = datetime.strptime(b['due_date'], '%Y-%m-%d').strftime('%d/%m')
                    lines.append(f"• {b['title']}: R$ {b['amount']:.2f} (venceu {due_fmt})")
                lines.append("")

            if today_bills:
                lines.append(f"📅 *Vencendo Hoje ({len(today_bills)}):*")
                for b in today_bills:
                    lines.append(f"• {b['title']}: R$ {b['amount']:.2f}")
                lines.append("")

            if upcoming:
                lines.append(f"⏳ *Próximos 3 Dias ({len(upcoming)}):*")
                for b in upcoming:
                    due_fmt = datetime.strptime(b['due_date'], '%Y-%m-%d').strftime('%d/%m')
                    lines.append(f"• {b['title']}: R$ {b['amount']:.2f} (vence {due_fmt})")
                lines.append("")

            lines.append(f"💰 *Total Pendente:* R$ {total_pending:.2f}")

        msg = "\n".join(lines)

        try:
            success = send_telegram_msg(bot_token, user_row["telegram_chat_id"], msg)
            if success:
                return {"message": "Resumo de vencimentos enviado para seu Telegram com sucesso!"}
            else:
                raise HTTPException(status_code=502, detail="Telegram recusou a mensagem. Verifique seu chat ID ou envie /start ao bot.")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            raise HTTPException(status_code=400, detail=f"Erro no Telegram: {err_msg}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Falha ao enviar resumo: {str(e)}")

@app.get("/api/telegram/cron-digest")
def cron_telegram_digest(authorization: Optional[str] = Header(None), secret: Optional[str] = Query(None)):
    token_candidate = None
    if authorization and authorization.startswith("Bearer "):
        token_candidate = authorization.split(" ", 1)[1].strip()
    elif secret:
        token_candidate = secret.strip()

    if token_candidate != CRON_SECRET:
        raise HTTPException(status_code=403, detail="Acesso não autorizado ao job de notificações")

    today_str = date.today().isoformat()
    sent_count = 0
    with get_db() as conn:
        users = conn.execute("""
            SELECT id, name, telegram_chat_id, telegram_bot_token
            FROM users
            WHERE telegram_notifications_enabled = 1 
              AND telegram_chat_id IS NOT NULL 
              AND telegram_chat_id != ''
        """).fetchall()

        for u in users:
            bot_token = u["telegram_bot_token"] or DEFAULT_TELEGRAM_BOT_TOKEN
            if not bot_token:
                continue
            bills = conn.execute("""
                SELECT title, amount, due_date
                FROM bills
                WHERE user_id = ? AND status = 'PENDING' AND due_date <= ?
                ORDER BY due_date ASC
            """, (u["id"], today_str)).fetchall()

            if not bills:
                continue

            lines = [
                f"🔔 *Lembrete Diário - Meu Financeiro*",
                f"Olá, *{u['name']}*! Você tem contas precisando de atenção hoje:\n"
            ]
            for b in bills:
                status_icon = "⚠️" if b["due_date"] < today_str else "📅"
                lines.append(f"{status_icon} *{b['title']}*: R$ {b['amount']:.2f}")

            msg = "\n".join(lines)
            try:
                if send_telegram_msg(bot_token, u["telegram_chat_id"], msg):
                    sent_count += 1
            except Exception:
                pass

    return {"message": f"Notificações enviadas para {sent_count} usuários."}

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

# Rota para carregar o frontend diretamente no Render / local / Vercel
@app.get("/", response_class=HTMLResponse)
def serve_index():
    for p in [
        os.path.join(BASE_DIR, "index.html"),
        "index.html",
        os.path.join(public_path, "index.html"),
        "public/index.html"
    ]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
    return HTMLResponse("<h1>API online. index.html não encontrado na raiz.</h1>", status_code=404)
