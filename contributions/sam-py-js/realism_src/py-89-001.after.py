import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "/var/lib/loja/loja.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def buscar_pedidos_cliente(conn, cliente_id, status):
    cur = conn.cursor()
    query = (
        "SELECT id, total, criado_em FROM pedidos "
        "WHERE cliente_id = ? AND status = ? "
        "ORDER BY criado_em DESC LIMIT 50"
    )
    cur.execute(query, (cliente_id, status))
    return [dict(r) for r in cur.fetchall()]


@app.route("/api/clientes/<int:cliente_id>/pedidos")
def listar_pedidos(cliente_id):
    status = request.args.get("status", "aberto")
    conn = get_conn()
    try:
        pedidos = buscar_pedidos_cliente(conn, cliente_id, status)
    finally:
        conn.close()
    return jsonify({"cliente": cliente_id, "pedidos": pedidos})
