interface Notificacao {
  id: string;
  titulo: string;
  mensagem: string;
  lida: boolean;
}

const painel = document.querySelector<HTMLDivElement>('#notificacoes')!;
const contador = document.querySelector<HTMLSpanElement>('#contador')!;

async function buscarNotificacoes(): Promise<Notificacao[]> {
  const resp = await fetch('/api/notificacoes', { credentials: 'same-origin' });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  return (await resp.json()) as Notificacao[];
}

function renderizar(lista: Notificacao[]): void {
  painel.innerHTML = lista
    .map((n) => `<div class="notif ${n.lida ? 'lida' : ''}"><h4>${n.titulo}</h4><p>${n.mensagem}</p></div>`)
    .join('');
  contador.textContent = String(lista.filter((n) => !n.lida).length);
}

async function atualizar(): Promise<void> {
  try {
    renderizar(await buscarNotificacoes());
  } catch (e) {
    painel.textContent = 'Falha ao carregar notificacoes';
  }
}

setInterval(atualizar, 30_000);
void atualizar();
