import gzip
import re
import shutil
import subprocess
from pathlib import Path

BACKUP_DIR = Path("/srv/backups")
NOME_OK = re.compile(r"^[a-zA-Z0-9_]{1,63}$")


def nome_arquivo_backup(banco, rotulo):
    return BACKUP_DIR / f"{banco}-{rotulo}.sql.gz"


def gerar_dump(banco, rotulo, usuario="backup"):
    if not NOME_OK.match(banco) or not NOME_OK.match(rotulo):
        raise ValueError("nome de banco ou rotulo invalido")
    destino = nome_arquivo_backup(banco, rotulo)
    proc = subprocess.Popen(
        ["pg_dump", "-U", usuario, "--", banco], stdout=subprocess.PIPE
    )
    with gzip.open(destino, "wb", compresslevel=9) as saida:
        shutil.copyfileobj(proc.stdout, saida)
    if proc.wait() != 0:
        destino.unlink(missing_ok=True)
        raise RuntimeError("pg_dump falhou")
    return destino


def tarefa_backup(payload):
    banco = payload["banco"]
    rotulo = payload.get("rotulo", "manual")
    caminho = gerar_dump(banco, rotulo)
    tamanho = caminho.stat().st_size if caminho.exists() else 0
    return {"arquivo": str(caminho), "bytes": tamanho}
