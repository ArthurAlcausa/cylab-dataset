import os
import mimetypes
from flask import Flask, request, abort, Response

app = Flask(__name__)
UPLOAD_ROOT = "/srv/app/uploads"


def tipo_conteudo(caminho):
    tipo, _ = mimetypes.guess_type(caminho)
    return tipo or "application/octet-stream"


def ler_anexo(nome):
    caminho = os.path.join(UPLOAD_ROOT, nome)
    if not os.path.isfile(caminho):
        return None, None
    with open(caminho, "rb") as fh:
        return fh.read(), tipo_conteudo(caminho)


@app.route("/anexos/download")
def baixar_anexo():
    nome = request.args.get("arquivo", "")
    if not nome:
        abort(400)
    conteudo, tipo = ler_anexo(nome)
    if conteudo is None:
        abort(404)
    resp = Response(conteudo, mimetype=tipo)
    resp.headers["Content-Disposition"] = "attachment"
    return resp
