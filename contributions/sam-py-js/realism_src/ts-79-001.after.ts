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

function criarItem(n: Notificacao): HTMLDivElement {
  const div = document.createElement('div');
  div.className = n.lida ? 'notif lida' : 'notif';
  const h4 = document.createElement('h4');
  h4.textContent = n.titulo;
  const p = document.createElement('p');
  p.textContent = n.mensagem;
  div.append(h4, p);
  return div;
}

function renderizar(lista: Notificacao[]): void {
  painel.replaceChildren(...lista.map(criarItem));
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
