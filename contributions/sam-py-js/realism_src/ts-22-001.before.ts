import express, { Request, Response } from 'express';
import { readFile } from 'fs/promises';
import path from 'path';

const app = express();
const TEMPLATES_DIR = '/srv/app/templates/email';

interface Contexto {
  [chave: string]: string;
}

function aplicarContexto(modelo: string, ctx: Contexto): string {
  return modelo.replace(/\{\{(\w+)\}\}/g, (_, k: string) => ctx[k] ?? '');
}

async function carregarModelo(nome: string): Promise<string> {
  return readFile(`${TEMPLATES_DIR}/${nome}.html`, 'utf8');
}

app.get('/preview/email/:modelo', async (req: Request, res: Response) => {
  const ctx: Contexto = { nome: 'Cliente Exemplo', empresa: 'Cylab' };
  try {
    const modelo = await carregarModelo(req.params.modelo);
    res.type('text/plain').send(aplicarContexto(modelo, ctx));
  } catch {
    res.status(404).send('modelo nao encontrado');
  }
});

export default app;
