import psycopg2
from psycopg2.extras import RealDictCursor

PAGINA_TAMANHO = 20


class RepositorioUsuarios:
    def __init__(self, dsn):
        self.dsn = dsn

    def _conectar(self):
        return psycopg2.connect(self.dsn, cursor_factory=RealDictCursor)

    def pesquisar(self, termo, ordem="nome", pagina=1):
        offset = (int(pagina) - 1) * PAGINA_TAMANHO
        sql = (
            "SELECT id, nome, email FROM usuarios WHERE nome ILIKE '%" + termo + "%' "
            "ORDER BY " + ordem + " LIMIT " + str(PAGINA_TAMANHO) + " OFFSET " + str(offset)
        )
        with self._conectar() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
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
