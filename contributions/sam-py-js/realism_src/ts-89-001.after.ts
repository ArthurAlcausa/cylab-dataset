import { Request, Response, Router } from 'express';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const faturasRouter = Router();

interface Fatura {
  id: number;
  cliente: string;
  valor: number;
  vencimento: string;
}

async function listarFaturas(clienteId: string, mes: string): Promise<Fatura[]> {
  const sql = `SELECT id, cliente, valor, vencimento FROM faturas
    WHERE cliente_id = $1 AND to_char(vencimento, 'YYYY-MM') = $2
    ORDER BY vencimento`;
  const { rows } = await pool.query(sql, [clienteId, mes]);
  return rows;
}

function totalizar(faturas: Fatura[]): number {
  return faturas.reduce((acc, f) => acc + Number(f.valor), 0);
}

faturasRouter.get('/clientes/:id/faturas', async (req: Request, res: Response) => {
  const mes = String(req.query.mes ?? new Date().toISOString().slice(0, 7));
  if (!/^\d{4}-\d{2}$/.test(mes)) {
    return res.status(400).json({ erro: 'mes invalido' });
  }
  try {
    const faturas = await listarFaturas(req.params.id, mes);
    res.json({ faturas, total: totalizar(faturas) });
  } catch (e) {
    res.status(500).json({ erro: 'falha ao consultar faturas' });
  }
});
