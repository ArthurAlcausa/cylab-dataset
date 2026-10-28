const express = require('express');
const { execFile } = require('child_process');
const path = require('path');

const app = express();
app.use(express.json());
const MIDIA_DIR = '/srv/midia';

function gerarMiniatura(arquivo, largura, callback) {
  const origem = path.join(MIDIA_DIR, path.basename(arquivo));
  const destino = origem.replace(/\.(\w+)$/, '_thumb.jpg');
  const px = Math.min(Math.max(parseInt(largura, 10) || 200, 16), 2048);
  execFile('convert', [origem, '-resize', `${px}x`, destino], (err, stdout, stderr) => {
    if (err) {
      return callback(new Error(stderr || err.message));
    }
    callback(null, destino);
  });
}

app.post('/midia/miniatura', (req, res) => {
  const { arquivo, largura } = req.body;
  if (!arquivo) {
    return res.status(400).json({ erro: 'arquivo obrigatorio' });
  }
  gerarMiniatura(arquivo, largura, (err, destino) => {
    if (err) {
      return res.status(500).json({ erro: 'falha ao converter' });
    }
    res.json({ miniatura: path.basename(destino) });
  });
});

module.exports = app;
