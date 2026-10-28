import ipaddress
import subprocess
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
log = logging.getLogger("diag")


def executar_ping(host, tentativas=3):
    alvo = str(ipaddress.ip_address(host))
    argv = ["ping", "-c", str(int(tentativas)), alvo]
    log.info("executando diagnostico: %s", argv)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    return proc.returncode, proc.stdout


def resumir_saida(saida):
    linhas = [l for l in saida.splitlines() if l.strip()]
    return linhas[-2:] if len(linhas) >= 2 else linhas


@app.route("/admin/diagnostico/ping", methods=["POST"])
def diagnostico_ping():
    dados = request.get_json(force=True)
    host = dados.get("host", "")
    try:
        codigo, saida = executar_ping(host)
    except ValueError:
        return jsonify({"erro": "host deve ser um IP valido"}), 400
    return jsonify({"ok": codigo == 0, "resumo": resumir_saida(saida)})
