const express = require('express');
const { exec } = require('child_process');
const path = require('path');

const app = express();
app.use(express.json());
const MIDIA_DIR = '/srv/midia';

function gerarMiniatura(arquivo, largura, callback) {
  const origem = path.join(MIDIA_DIR, path.basename(arquivo));
  const destino = origem.replace(/\.(\w+)$/, '_thumb.jpg');
  exec(`convert ${origem} -resize ${largura}x ${destino}`, (err, stdout, stderr) => {
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
  gerarMiniatura(arquivo, largura || 200, (err, destino) => {
    if (err) {
      return res.status(500).json({ erro: 'falha ao converter' });
    }
    res.json({ miniatura: path.basename(destino) });
  });
});

module.exports = app;
