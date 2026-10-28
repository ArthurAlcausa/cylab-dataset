import { DataSource } from 'typeorm';

export class AuditoriaService {
  constructor(private readonly ds: DataSource) {}

  async buscarEventos(usuario: string, acao?: string, limite = 100) {
    const teto = Math.min(limite, 500);
    if (acao) {
      return this.ds.query(
        'SELECT id, usuario, acao, criado_em FROM auditoria WHERE usuario = $1 AND acao = $2 ORDER BY criado_em DESC LIMIT $3',
        [usuario, acao, teto],
      );
    }
    return this.ds.query(
      'SELECT id, usuario, acao, criado_em FROM auditoria WHERE usuario = $1 ORDER BY criado_em DESC LIMIT $2',
      [usuario, teto],
    );
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
