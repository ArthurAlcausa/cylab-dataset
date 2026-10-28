import os
import mimetypes
from flask import Flask, request, abort, Response

app = Flask(__name__)
UPLOAD_ROOT = "/srv/app/uploads"


def tipo_conteudo(caminho):
    tipo, _ = mimetypes.guess_type(caminho)
    return tipo or "application/octet-stream"


def ler_anexo(nome):
    raiz = os.path.realpath(UPLOAD_ROOT)
    caminho = os.path.realpath(os.path.join(raiz, nome))
    if os.path.commonpath([raiz, caminho]) == raiz and os.path.isfile(caminho):
        with open(caminho, "rb") as fh:
            return fh.read(), tipo_conteudo(caminho)
    return None, None


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
