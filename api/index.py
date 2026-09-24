import sys
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Adiciona o diretório raiz ao path para importar main
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from main import app

# Adicione ou garanta que este bloco esteja no final do arquivo api/index.py
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
static_path = os.path.join(root_dir, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/")
def serve_home():
    html_file = os.path.join(static_path, "index.html")
    if os.path.exists(html_file):
        return FileResponse(html_file)
    return {"message": "API online. Coloque o index.html na pasta static."}
