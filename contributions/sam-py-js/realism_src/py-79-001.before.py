from flask import Flask, request, render_template_string
from markupsafe import Markup

app = Flask(__name__)

PRODUTOS = {
    "1": {"nome": "Teclado", "preco": 199.9},
    "2": {"nome": "Mouse", "preco": 89.0},
}


def buscar(termo):
    termo = termo.lower()
    return [p for p in PRODUTOS.values() if termo in p["nome"].lower()]


def montar_lista(itens):
    linhas = []
    for p in itens:
        linhas.append(f"<li>{p['nome']} - R$ {p['preco']:.2f}</li>")
    return "\n".join(linhas)


@app.route("/busca")
def pagina_busca():
    termo = request.args.get("q", "")
    itens = buscar(termo)
    html = "<h1>Resultados para " + termo + "</h1><ul>" + montar_lista(itens) + "</ul>"
    return Markup(html)
