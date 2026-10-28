const express = require('express');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({ host: 'db', user: 'app', database: 'loja', connectionLimit: 10 });
const router = express.Router();

async function buscarProdutos(categoria, precoMax) {
  const sql = 'SELECT id, nome, preco FROM produtos WHERE categoria = ? AND preco <= ? ORDER BY preco';
  const [rows] = await pool.execute(sql, [String(categoria), Number(precoMax)]);
  return rows;
}

function formatarProduto(p) {
  return { id: p.id, nome: p.nome, preco: Number(p.preco).toFixed(2) };
}

router.get('/produtos', async (req, res) => {
  const categoria = req.query.categoria || 'geral';
  const precoMax = Number.parseFloat(req.query.max || '1000');
  if (Number.isNaN(precoMax)) {
    return res.status(400).json({ erro: 'max invalido' });
  }
  try {
    const rows = await buscarProdutos(categoria, precoMax);
    res.json(rows.map(formatarProduto));
  } catch (err) {
    console.error('falha na busca', err);
    res.status(500).json({ erro: 'erro interno' });
  }
});

module.exports = router;
