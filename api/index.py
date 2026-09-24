import sys
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Adiciona o diretório raiz ao path para importar main
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from main import app

# Configuração de arquivos estáticos (suporta tanto public/ quanto static/)
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
public_path = os.path.join(root_dir, "public")
static_path = os.path.join(root_dir, "static")

if os.path.exists(public_path):
    try:
        app.mount("/public", StaticFiles(directory=public_path), name="public")
    except Exception:
        pass

if os.path.exists(static_path):
    try:
        app.mount("/static", StaticFiles(directory=static_path), name="static")
    except Exception:
        pass

@app.get("/")
def serve_home():
    for p in [
        os.path.join(public_path, "index.html"),
        os.path.join(static_path, "index.html"),
        "public/index.html",
        "static/index.html"
    ]:
        if os.path.exists(p):
            return FileResponse(p)
    return {"message": "API online. Coloque o index.html na pasta public ou static."}
