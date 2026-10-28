from flask import Flask, request, render_template_string

app = Flask(__name__)

PRODUTOS = {
    "1": {"nome": "Teclado", "preco": 199.9},
    "2": {"nome": "Mouse", "preco": 89.0},
}

PAGINA = """<h1>Resultados para {{ termo }}</h1>
<ul>{% for p in itens %}<li>{{ p.nome }} - R$ {{ '%.2f' % p.preco }}</li>{% endfor %}</ul>"""


def buscar(termo):
    termo = termo.lower()
    return [p for p in PRODUTOS.values() if termo in p["nome"].lower()]


def normalizar_termo(termo):
    return termo.strip()[:100]


@app.route("/busca")
def pagina_busca():
    termo = normalizar_termo(request.args.get("q", ""))
    itens = buscar(termo)
    return render_template_string(PAGINA, termo=termo, itens=itens)
