const express = require('express');
const fs = require('fs/promises');
const path = require('path');

const router = express.Router();
const RELATORIOS_DIR = path.resolve('/srv/relatorios');

async function lerRelatorio(tenant, nome) {
  const base = path.resolve(RELATORIOS_DIR, tenant);
  const caminho = path.resolve(base, nome);
  if (!caminho.startsWith(base + path.sep)) {
    throw new Error('caminho fora do diretorio do tenant');
  }
  const stat = await fs.stat(caminho);
  if (!stat.isFile()) {
    throw new Error('nao e arquivo');
  }
  return fs.readFile(caminho);
}

function exigirTenant(req, res, next) {
  if (!req.user || !req.user.tenant) {
    return res.status(401).end();
  }
  next();
}

router.get('/relatorios/:nome', exigirTenant, async (req, res) => {
  try {
    const dados = await lerRelatorio(req.user.tenant, req.params.nome);
    res.type('application/pdf').send(dados);
  } catch (err) {
    res.status(404).json({ erro: 'relatorio nao encontrado' });
  }
});

module.exports = router;
