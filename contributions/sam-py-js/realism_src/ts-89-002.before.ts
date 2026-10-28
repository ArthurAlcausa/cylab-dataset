import { DataSource } from 'typeorm';

export class AuditoriaService {
  constructor(private readonly ds: DataSource) {}

  async buscarEventos(usuario: string, acao?: string, limite = 100) {
    let filtro = "usuario = '" + usuario + "'";
    if (acao) {
      filtro += " AND acao = '" + acao + "'";
    }
    const sql = 'SELECT id, usuario, acao, criado_em FROM auditoria WHERE ' + filtro +
      ' ORDER BY criado_em DESC LIMIT ' + Math.min(limite, 500);
    return this.ds.query(sql);
  }

  async registrar(usuario: string, acao: string, detalhe: object) {
    await this.ds.query(
      'INSERT INTO auditoria (usuario, acao, detalhe) VALUES ($1, $2, $3)',
      [usuario, acao, JSON.stringify(detalhe)],
    );
  }
}

export async function handlerAuditoria(svc: AuditoriaService, query: Record<string, string>) {
  if (!query.usuario) {
    return { status: 400, body: { erro: 'usuario obrigatorio' } };
  }
  const eventos = await svc.buscarEventos(query.usuario, query.acao);
  return { status: 200, body: { eventos } };
}
