import os
import shutil
import tempfile
from pathlib import Path

BACKUP_DIR = Path("/srv/backups")


def nome_arquivo_backup(banco, rotulo):
    return BACKUP_DIR / f"{banco}-{rotulo}.sql.gz"


def gerar_dump(banco, rotulo, usuario="backup"):
    destino = nome_arquivo_backup(banco, rotulo)
    tmp = tempfile.mkdtemp(prefix="dump-")
    try:
        bruto = os.path.join(tmp, "dump.sql")
        os.system("pg_dump -U " + usuario + " " + banco + " > " + bruto)
        os.system("gzip -9 " + bruto)
        shutil.move(bruto + ".gz", destino)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return destino


def tarefa_backup(payload):
    banco = payload["banco"]
    rotulo = payload.get("rotulo", "manual")
    caminho = gerar_dump(banco, rotulo)
    tamanho = caminho.stat().st_size if caminho.exists() else 0
    return {"arquivo": str(caminho), "bytes": tamanho}
