import sqlite3
import calendar
import io
import csv
import os
import shutil
from datetime import date, datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

app = FastAPI(title="Painel Financeiro Pessoal")

if os.environ.get("VERCEL"):
    DB_NAME = "/tmp/finance.db"
    UPLOAD_DIR = "/tmp/uploads"
else:
    DB_NAME = "finance.db"
    UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                amount REAL NOT NULL,
                receive_date DATE NOT NULL,
                is_recurring BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS category_budgets (
                category TEXT PRIMARY KEY,
                budget_limit REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS saving_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target_amount REAL NOT NULL,
                current_amount REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migração segura para colunas novas
        for col_def in ["amount_paid REAL", "account TEXT DEFAULT 'Geral'", "receipt_path TEXT"]:
            try:
                conn.execute(f"ALTER TABLE bills ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass
        conn.commit()

init_db()

# Modelos
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

# --- ROTAS DE DESPESAS ---
@app.get("/api/bills")
def list_bills(month: Optional[int] = None, year: Optional[int] = None):
    with get_db() as conn:
        if month and year:
            prefix = f"{year:04d}-{month:02d}%"
            rows = conn.execute("SELECT * FROM bills WHERE due_date LIKE ? ORDER BY due_date ASC", (prefix,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM bills ORDER BY due_date ASC").fetchall()
        return [dict(row) for row in rows]

@app.post("/api/bills")
def add_bill(bill: BillCreate):
    with get_db() as conn:
        start_date = datetime.strptime(bill.due_date, "%Y-%m-%d").date()
        total_inst = bill.total_installments or 1
        account_val = bill.account or "Geral"

        if total_inst > 1:
            records = []
            for i in range(total_inst):
                due = add_months_safe(start_date, i)
                records.append((
                    bill.title, bill.category, bill.amount, due.isoformat(),
                    i + 1, total_inst, 0, bill.payment_code, account_val, "PENDING"
                ))
            conn.executemany("""
                INSERT INTO bills (title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
        else:
            conn.execute("""
                INSERT INTO bills (title, category, amount, due_date, current_installment, total_installments, is_recurring, payment_code, account, status)
                VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?, 'PENDING')
            """, (bill.title, bill.category, bill.amount, bill.due_date, 1 if bill.is_recurring else 0, bill.payment_code, account_val))

        conn.commit()
        return {"message": "Despesa cadastrada com sucesso"}

@app.put("/api/bills/{bill_id}")
def update_bill(bill_id: int, bill: BillUpdate, cascade: bool = Query(False)):
    with get_db() as conn:
        current = conn.execute("SELECT * FROM bills WHERE id = ?", (bill_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        if cascade and current["total_installments"] and current["total_installments"] > 1:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, account = ?, payment_code = ?
                WHERE title = ? AND total_installments = ? AND current_installment >= ?
            """, (bill.title, bill.category, bill.amount, bill.account or "Geral", bill.payment_code,
                  current["title"], current["total_installments"], current["current_installment"]))
            conn.execute("UPDATE bills SET due_date = ? WHERE id = ?", (bill.due_date, bill_id))
        else:
            conn.execute("""
                UPDATE bills
                SET title = ?, category = ?, amount = ?, due_date = ?, account = ?, payment_code = ?
                WHERE id = ?
            """, (bill.title, bill.category, bill.amount, bill.due_date, bill.account or "Geral", bill.payment_code, bill_id))

        conn.commit()
        return {"message": "Conta atualizada"}

@app.delete("/api/bills/{bill_id}")
def delete_bill(bill_id: int, cascade: bool = Query(False)):
    with get_db() as conn:
        current = conn.execute("SELECT * FROM bills WHERE id = ?", (bill_id,)).fetchone()
        if not current:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        # Remove comprovante se houver
        if current["receipt_path"] and os.path.exists(current["receipt_path"]):
            try:
                os.remove(current["receipt_path"])
            except OSError:
                pass

        if cascade and current["total_installments"] and current["total_installments"] > 1:
            conn.execute("""
                DELETE FROM bills
                WHERE title = ? AND total_installments = ? AND current_installment >= ?
            """, (current["title"], current["total_installments"], current["current_installment"]))
        else:
            conn.execute("DELETE FROM bills WHERE id = ?", (bill_id,))

        conn.commit()
        return {"message": "Removido com sucesso"}

# Pagamento e Upload de Comprovante
@app.post("/api/bills/{bill_id}/pay-upload")
async def pay_and_upload(
    bill_id: int,
    amount_paid: Optional[float] = Form(None),
    receipt: Optional[UploadFile] = File(None)
):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM bills WHERE id = ?", (bill_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Conta não encontrada")

        actual_paid = amount_paid if amount_paid is not None else row["amount"]
        receipt_path = row["receipt_path"]

        if receipt and receipt.filename:
            ext = os.path.splitext(receipt.filename)[1]
            saved_filename = f"receipt_{bill_id}_{int(datetime.now().timestamp())}{ext}"
            file_location = os.path.join(UPLOAD_DIR, saved_filename)
            with open(file_location, "wb+") as f:
                shutil.copyfileobj(receipt.file, f)
            receipt_path = file_location

        conn.execute("""
            UPDATE bills
            SET status = 'PAID', amount_paid = ?, receipt_path = ?
            WHERE id = ?
        """, (actual_paid, receipt_path, bill_id))
        conn.commit()
        return {"message": "Pagamento confirmado com sucesso", "status": "PAID", "receipt_path": receipt_path}

@app.patch("/api/bills/{bill_id}/unpay")
def unpay_bill(bill_id: int):
    with get_db() as conn:
        conn.execute("UPDATE bills SET status = 'PENDING', amount_paid = NULL WHERE id = ?", (bill_id,))
        conn.commit()
        return {"message": "Pagamento desfeito"}

@app.get("/api/bills/{bill_id}/receipt")
def get_receipt(bill_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT receipt_path FROM bills WHERE id = ?", (bill_id,)).fetchone()
        if not row or not row["receipt_path"] or not os.path.exists(row["receipt_path"]):
            raise HTTPException(status_code=404, detail="Comprovante não encontrado")
        return FileResponse(row["receipt_path"])

@app.post("/api/bills/copy-recurring")
def copy_recurring(month: int, year: int):
    prev_month = 12 if month == 1 else month - 1
    prev_year = year - 1 if month == 1 else year
    prev_prefix = f"{prev_year:04d}-{prev_month:02d}%"

    with get_db() as conn:
        recurring = conn.execute(
            "SELECT title, category, amount, due_date, payment_code, account FROM bills WHERE is_recurring = 1 AND due_date LIKE ?",
            (prev_prefix,)
        ).fetchall()

        count = 0
        for b in recurring:
            orig_day = int(b["due_date"].split("-")[2])
            max_day = calendar.monthrange(year, month)[1]
            day = min(orig_day, max_day)
            new_due_date = f"{year:04d}-{month:02d}-{day:02d}"

            exists = conn.execute("SELECT id FROM bills WHERE title = ? AND due_date = ?", (b["title"], new_due_date)).fetchone()
            if not exists:
                conn.execute("""
                    INSERT INTO bills (title, category, amount, due_date, is_recurring, payment_code, account, status)
                    VALUES (?, ?, ?, ?, 1, ?, ?, 'PENDING')
                """, (b["title"], b["category"], b["amount"], new_due_date, b["payment_code"], b["account"]))
                count += 1

        conn.commit()
        return {"message": f"{count} conta(s) recorrente(s) importada(s)."}

# --- RECEITAS ---
@app.get("/api/incomes")
def list_incomes(month: int, year: int):
    prefix = f"{year:04d}-{month:02d}%"
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM incomes WHERE receive_date LIKE ? ORDER BY receive_date ASC", (prefix,)).fetchall()
        return [dict(r) for r in rows]

@app.post("/api/incomes")
def add_income(income: IncomeCreate):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO incomes (title, amount, receive_date, is_recurring)
            VALUES (?, ?, ?, ?)
        """, (income.title, income.amount, income.receive_date, 1 if income.is_recurring else 0))
        conn.commit()
        return {"message": "Receita registrada"}

@app.delete("/api/incomes/{income_id}")
def delete_income(income_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM incomes WHERE id = ?", (income_id,))
        conn.commit()
        return {"message": "Receita excluída"}

# --- CAIXINHAS / METAS DE RESERVA ---
@app.get("/api/goals")
def list_goals():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM saving_goals ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

@app.post("/api/goals")
def create_goal(goal: GoalCreate):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO saving_goals (name, target_amount, current_amount)
            VALUES (?, ?, ?)
        """, (goal.name, goal.target_amount, goal.current_amount or 0.0))
        conn.commit()
        return {"message": "Meta criada com sucesso"}

@app.post("/api/goals/{goal_id}/deposit")
def deposit_goal(goal_id: int, dep: GoalDeposit):
    with get_db() as conn:
        conn.execute("""
            UPDATE saving_goals
            SET current_amount = MAX(0, current_amount + ?)
            WHERE id = ?
        """, (dep.amount, goal_id))
        conn.commit()
        return {"message": "Saldo da caixinha atualizado"}

@app.delete("/api/goals/{goal_id}")
def delete_goal(goal_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM saving_goals WHERE id = ?", (goal_id,))
        conn.commit()
        return {"message": "Meta removida"}

# --- TETOS, PROJEÇÃO E MATRIZ ANUAL ---
@app.get("/api/budgets")
def get_budgets():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM category_budgets").fetchall()
        return {r["category"]: r["budget_limit"] for r in rows}

@app.post("/api/budgets")
def set_budget(budget: BudgetSet):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO category_budgets (category, budget_limit)
            VALUES (?, ?)
            ON CONFLICT(category) DO UPDATE SET budget_limit = excluded.budget_limit
        """, (budget.category, budget.budget_limit))
        conn.commit()
        return {"message": "Teto configurado"}

@app.get("/api/dashboard/annual")
def get_annual_matrix(year: int):
    month_names = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    result = []
    with get_db() as conn:
        for m in range(1, 13):
            prefix = f"{year:04d}-{m:02d}%"
            exp_row = conn.execute("SELECT SUM(COALESCE(amount_paid, amount)) as total FROM bills WHERE due_date LIKE ?", (prefix,)).fetchone()
            expenses = exp_row["total"] or 0.0

            inc_row = conn.execute("SELECT SUM(amount) as total FROM incomes WHERE receive_date LIKE ?", (prefix,)).fetchone()
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
def get_projection(start_month: int, start_year: int):
    results = []
    curr_date = date(start_year, start_month, 1)
    with get_db() as conn:
        for i in range(6):
            m_date = add_months_safe(curr_date, i)
            prefix = f"{m_date.year:04d}-{m_date.month:02d}%"
            row = conn.execute("SELECT SUM(COALESCE(amount_paid, amount)) as total FROM bills WHERE due_date LIKE ?", (prefix,)).fetchone()
            total = row["total"] or 0.0
            month_names = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]
            label = f"{month_names[m_date.month - 1]}/{str(m_date.year)[2:]}"
            results.append({"month_label": label, "total": total})
    return results

@app.get("/api/export/csv")
def export_csv(month: int, year: int):
    prefix = f"{year:04d}-{month:02d}%"
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM bills WHERE due_date LIKE ? ORDER BY due_date ASC", (prefix,)).fetchall()

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
def download_backup():
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
        // Pass-through sem bloquear requisições dinâmicas
        e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    });
    """
    return Response(content=content, media_type="application/javascript")

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    return FileResponse("static/index.html")