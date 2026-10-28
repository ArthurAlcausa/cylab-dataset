import psycopg2
from psycopg2.extras import RealDictCursor

ORDENACOES = {"nome", "criado_em", "email"}


class RepositorioUsuarios:
    def __init__(self, dsn):
        self.dsn = dsn

    def _conectar(self):
        return psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)

    def pesquisar(self, termo, ordem="nome", pagina=1):
        if ordem not in ORDENACOES:
            ordem = "nome"
        offset = (int(pagina) - 1) * 20
        sql = (
            "SELECT id, nome, email FROM usuarios WHERE nome ILIKE %s "
            "ORDER BY {} LIMIT 20 OFFSET %s"
        ).format(ordem)
        with self._conectar() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, ("%" + termo + "%", offset))
                return cur.fetchall()

    def contar_ativos(self):
        with self._conectar() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) AS n FROM usuarios WHERE ativo")
                return cur.fetchone()["n"]


def handler_busca(repo, params):
    termo = params.get("q", "")
    resultados = repo.pesquisar(termo, params.get("ordem", "nome"), params.get("p", 1))
    return {"total": len(resultados), "itens": resultados}
