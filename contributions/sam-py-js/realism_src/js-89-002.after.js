const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function encontrarUsuario(login) {
  const result = await pool.query('SELECT id, login, senha_hash, papel FROM usuarios WHERE login = $1', [login]);
  return result.rows[0] || null;
}

async function registrarTentativa(usuarioId, sucesso) {
  await pool.query('INSERT INTO tentativas_login (usuario_id, sucesso) VALUES ($1, $2)', [usuarioId, sucesso]);
}

async function autenticar(req, res) {
  const { login, senha } = req.body || {};
  if (typeof login !== 'string' || typeof senha !== 'string') {
    return res.status(400).json({ erro: 'credenciais ausentes' });
  }
  const usuario = await encontrarUsuario(login);
  if (!usuario) {
    return res.status(401).json({ erro: 'login invalido' });
  }
  const ok = await bcrypt.compare(senha, usuario.senha_hash);
  await registrarTentativa(usuario.id, ok);
  if (!ok) {
    return res.status(401).json({ erro: 'login invalido' });
  }
  req.session.usuarioId = usuario.id;
  return res.json({ id: usuario.id, papel: usuario.papel });
}

module.exports = { autenticar };
