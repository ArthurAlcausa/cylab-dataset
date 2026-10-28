import json,os,subprocess,sys,statistics,glob
sys.path.insert(0,'/workspace/cylab-dataset/scripts')
from gold_near_dup import norm_tokens,shingles,jacc
ROOT='/workspace/cylab-dataset'; OG=os.path.expanduser('~/.opengrep/cli/latest/opengrep')
L={'py':'python','js':'javascript','ts':'typescript'}
RULE={'py-89':'sql-injection','py-78':'command-injection','py-22':'path-traversal','py-79':'flask-unsafe-html',
 'js-89':'sql-injection','js-78':'command-injection','js-22':'path-traversal','js-79':'xss-innerhtml',
 'ts-89':'sql-injection','ts-79':'innerhtml-assign','ts-22':'readfile-template-path'}
EXP={
'py-89-001':'A função monta a consulta com f-string interpolando cliente_id e status vindos da URL, o que permite injeção de SQL (CWE-89). A correção usa placeholders (?) com parâmetros vinculados e restringe o id a inteiro na rota.',
'py-89-002':'O termo de busca e o campo de ordenação são concatenados no SQL, permitindo injeção de SQL (CWE-89). A correção passa o termo como parâmetro (%s) e só interpola a coluna de ordenação depois de validá-la contra uma allowlist.',
'py-78-001':'O host recebido no JSON é interpolado num comando executado com shell=True, permitindo injeção de comandos do SO (CWE-78). A correção valida o host como IP e executa ping com lista de argumentos, sem shell.',
'py-78-002':'O nome do banco e do rótulo entram em strings passadas a os.system, permitindo injetar comandos (CWE-78). A correção valida os nomes por regex, usa subprocess sem shell e faz a compressão em Python.',
'py-22-001':'O nome do arquivo da query string é unido ao diretório de uploads sem validação, permitindo path traversal com ../ (CWE-22). A correção resolve o caminho real e confere com os.path.commonpath que ele permanece dentro da raiz.',
'py-79-001':'O termo de busca é concatenado em HTML e marcado como seguro com Markup, gerando XSS refletido (CWE-79). A correção usa template Jinja com autoescape para o termo e os itens.',
'js-89-001':'Categoria e preço da query string são concatenados no SQL do MySQL, permitindo injeção de SQL (CWE-89). A correção usa pool.execute com placeholders ? e valida o preço como número.',
'js-89-002':'O login é interpolado em template literal na consulta do Postgres durante a autenticação, permitindo bypass via injeção de SQL (CWE-89). A correção usa o parâmetro $1 e checa o tipo das credenciais.',
'js-78-001':'Nome do arquivo e largura são interpolados num comando executado por exec (shell), permitindo injeção de comandos (CWE-78). A correção usa execFile com array de argumentos e normaliza a largura para inteiro limitado.',
'js-22-001':'O parâmetro :nome é unido ao diretório do tenant com path.join sem checagem, permitindo ler arquivos de outros tenants ou do sistema (CWE-22). A correção resolve o caminho e exige que ele comece pelo diretório base do tenant.',
'js-79-001':'Autor e texto dos comentários vindos da API são inseridos via innerHTML, gerando XSS armazenado (CWE-79). A correção cria os elementos via DOM e usa textContent.',
'ts-89-001':'clienteId e mes são interpolados no template literal SQL passado ao pool.query, permitindo injeção de SQL (CWE-89). A correção usa parâmetros $1/$2 e valida o formato do mês.',
'ts-89-002':'Os filtros de usuário e ação são concatenados na query bruta do TypeORM, permitindo injeção de SQL (CWE-89). A correção usa consultas fixas com parâmetros posicionais.',
'ts-79-001':'Título e mensagem das notificações são montados em template string e atribuídos a innerHTML, permitindo XSS (CWE-79). A correção constrói os nós com createElement e textContent.',
'ts-22-001':'O nome do modelo vindo da URL é interpolado no caminho do readFile, permitindo path traversal (CWE-22). A correção restringe a uma allowlist de modelos e usa path.basename.',
}
HOLD={'js-22-001','ts-79-001','py-78-002'}
def hits(rule,f):
    r=f'{ROOT}/rules-gold/{rule}.yaml'
    if not os.path.exists(r): r=f'{ROOT}/rules/{rule}.yaml'
    o=subprocess.run([OG,'scan','--config',r,f,'--json','-q'],capture_output=True,text=True).stdout
    return len(json.loads(o)['results'])
gold=[json.loads(l) for l in open(f'{ROOT}/data/cylab-commercial-v0.3-gold.jsonl')]
out=[];prog=dict(pairs=[],near_dup_drops=[],gate_failures=[])
for b in sorted(glob.glob('realism_src/*.before.*')):
    key=os.path.basename(b).split('.')[0]; l,cwe,n=key.split('-'); lang=L[l]; ext=b.rsplit('.',1)[1]
    a=b.replace('.before.','.after.'); rule=f'cylab.{lang}.{RULE[l+"-"+cwe]}'
    bt,at=open(b).read(),open(a).read(); hb,ha=hits(rule,b),hits(rule,a)
    sh=shingles(norm_tokens(bt,lang)); sim=max([jacc(sh,shingles(norm_tokens(g['before'],lang))) for g in gold if g['lang']==lang] or [0])
    rec=dict(id=f'cylab-sam-real-{key}',rule=rule,before_hits=hb,after_hits=ha,gate=hb>=1 and ha==0,max_sim_vs_final=round(sim,4),before_lines=bt.count('\n'),after_lines=at.count('\n'))
    prog['pairs'].append(rec)
    if not rec['gate']: prog['gate_failures'].append(rec['id']); continue
    if sim>=0.85: prog['near_dup_drops'].append(rec['id']); continue
    out.append(dict(id=rec['id'],lang=lang,cwe=f'CWE-{cwe}',source=f'sintetico-cylab https://cwe.mitre.org/data/definitions/{cwe}.html',license='CC-BY-4.0',opengrep_rule=rule,before=bt,after=at,explanation_pt=EXP[key],split='holdout' if key in HOLD else 'train'))
with open('gold_realism_v0.4_candidates.jsonl','w') as f:
    for p in out: f.write(json.dumps(p,ensure_ascii=False)+'\n')
P=[p for p in prog['pairs'] if p['id'] in {o['id'] for o in out}]
bl=[p['before_lines'] for p in P]; al=[p['after_lines'] for p in P]
prog.update(total_drafted=len(prog['pairs']),passed=len(out),by_lang={x:sum(o['lang']==x for o in out) for x in L.values()},
 by_cwe={c:sum(o['cwe']==c for o in out) for c in sorted({o['cwe'] for o in out})},splits={s:sum(o['split']==s for o in out) for s in ('train','holdout')},
 near_dup_threshold=0.85,near_dup_method='Jaccard 4-gram normalized tokens (scripts/gold_near_dup.py) vs FINAL v0.3 gold before, same lang',
 max_similarity_observed=max(p['max_sim_vs_final'] for p in P),
 line_stats=dict(before=dict(min=min(bl),median=statistics.median(bl),max=max(bl)),after=dict(min=min(al),median=statistics.median(al),max=max(al))),
 gate='opengrep before>=1 and after==0, rules-gold preferred',opengrep=OG)
json.dump(prog,open('gold_realism_progress.json','w'),indent=2,ensure_ascii=False)
print(json.dumps({k:v for k,v in prog.items() if k!='pairs'},indent=1))
