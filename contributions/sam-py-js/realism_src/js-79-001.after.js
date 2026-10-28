const API_BASE = '/api/v1';

async function carregarComentarios(postId) {
  const resp = await fetch(`${API_BASE}/posts/${encodeURIComponent(postId)}/comentarios`);
  if (!resp.ok) {
    throw new Error('falha ao carregar comentarios');
  }
  return resp.json();
}

function formatarData(iso) {
  return new Date(iso).toLocaleString('pt-BR');
}

function renderizarComentarios(lista, container) {
  container.replaceChildren();
  for (const c of lista) {
    const item = document.createElement('li');
    item.className = 'comentario';
    const autor = document.createElement('strong');
    autor.textContent = c.autor;
    const quando = document.createElement('time');
    quando.textContent = formatarData(c.criadoEm);
    const texto = document.createElement('p');
    texto.textContent = c.texto;
    item.append(autor, ' ', quando, texto);
    container.appendChild(item);
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  const container = document.getElementById('lista-comentarios');
  const postId = container.dataset.postId;
  try {
    renderizarComentarios(await carregarComentarios(postId), container);
  } catch (err) {
    container.textContent = 'Nao foi possivel carregar os comentarios.';
  }
});
