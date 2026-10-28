#!/usr/bin/env python3
"""Near-dup clustering para Cylab gold.
Normalizacao (leve): remove comentarios, literais string->S, numeros->N, identificadores nao-keyword->ID, colapsa espaco.
Cluster (dentro de mesmo lang+cwe): union-find sobre (a) hash identico do before normalizado, ou (b) Jaccard de 4-gramas de tokens >= THR (default 0.85).
Recomendacao: mantem ate K exemplares (default 2) por cluster, escolhendo primeiro fontes nao-template (nao 'bill'), depois maximizando diversidade do after normalizado; demais = drop.
Uso: gold_near_dup.py in.jsonl [--out report.json] [--thr 0.85] [--keep 2] [--against kept.jsonl]"""
import json,re,sys,hashlib,collections,itertools
KW=set("""def class return if else elif for while in not and or is None True False import from as with try except finally raise lambda yield async await pass break continue
function const let var new this typeof instanceof export default require module public private protected static void int long String boolean throws throw extends implements interface package
echo print array fn null true false self static use namespace include require_once include_once isset empty match case switch catch val char double float byte short final abstract""".split())
TOK=re.compile(r'''("""[\s\S]*?"""|'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|(\$?[A-Za-z_][A-Za-z0-9_]*)|(\d+(?:\.\d+)?)|(\S)''')
def strip_comments(s,lang):
    if lang in("python","bash"): s=re.sub(r'(?m)^\s*#.*$','',s)
    else: s=re.sub(r'/\*[\s\S]*?\*/','',s); s=re.sub(r'(?m)^\s*//.*$','',s)
    return s
def norm_tokens(s,lang):
    out=[]
    for m in TOK.finditer(strip_comments(s,lang)):
        st,idn,num,op=m.groups()
        if st is not None: out.append("S" if not KEEPSTR else "S:"+re.sub(r"\s+"," ",st[1:-1].lower()))
        elif idn is not None: out.append(idn if idn.lstrip("$") in KW else "ID")
        elif num is not None: out.append("N")
        else: out.append(op)
    return out
KEEPSTR=False
def norm_l2(s,lang):
    global KEEPSTR; KEEPSTR=True
    try: return norm_tokens(s,lang)
    finally: KEEPSTR=False
def shingles(t,k=4): return set(tuple(t[i:i+k]) for i in range(max(1,len(t)-k+1)))
def jacc(a,b): return len(a&b)/len(a|b) if a|b else 1.0
class UF:
    def __init__(s,n): s.p=list(range(n))
    def f(s,x):
        while s.p[x]!=x: s.p[x]=s.p[s.p[x]]; x=s.p[x]
        return x
    def u(s,a,b): s.p[s.f(a)]=s.f(b)
def tier(p):  # menor = preferido
    i=p["id"]; return 2 if "-bill-" in i else 1 if ("-sam" in i or "-mk-" in i) else 0
def cluster(P,thr=0.85,keep=2):
    T=[norm_tokens(p["before"],p["lang"]) for p in P]; H=[hashlib.sha1(" ".join(t).encode()).hexdigest()[:12] for t in T]
    SH=[shingles(t) for t in T]; AH=[hashlib.sha1(" ".join(norm_tokens(p["after"],p["lang"])).encode()).hexdigest()[:12] for p in P]
    L2=[hashlib.sha1(" ".join(norm_l2(p["before"],p["lang"])).encode()).hexdigest()[:12] for p in P]
    uf=UF(len(P)); g=collections.defaultdict(list); edge={}
    for i,p in enumerate(P): g[(p["lang"],p["cwe"])].append(i)
    for idx in g.values():
        for a,b in itertools.combinations(idx,2):
            if H[a]==H[b]: uf.u(a,b); edge[(a,b)]=1.0
            else:
                j=jacc(SH[a],SH[b])
                if j>=thr: uf.u(a,b); edge[(a,b)]=j
    cl=collections.defaultdict(list)
    for i in range(len(P)): cl[uf.f(i)].append(i)
    clusters=[]; decision={}
    for root,mem in cl.items():
        if len(mem)==1: decision[mem[0]]="keep"; continue
        exact=len(set(H[m] for m in mem))==1
        k=1 if (exact and len(set(AH[m] for m in mem))==1 and len(set(L2[m] for m in mem))==1) else keep
        order=sorted(mem,key=lambda m:(tier(P[m]),P[m]["id"]))
        chosen=[]; seenA=set()
        for m in order:   # primeiro: diversidade de after
            if len(chosen)<k and AH[m] not in seenA: chosen.append(m); seenA.add(AH[m])
        seenL=set(L2[m] for m in chosen)
        for m in order:
            if len(chosen)<k and m not in chosen and L2[m] not in seenL: chosen.append(m); seenL.add(L2[m])
        for m in order:
            if len(chosen)<k and m not in chosen: chosen.append(m)
        for m in mem: decision[m]="keep" if m in chosen else "drop"
        sims=[v for (a,b),v in edge.items() if a in mem and b in mem]
        clusters.append(dict(cluster_id=f"nd-{len(clusters)+1:04d}",lang=P[mem[0]]["lang"],cwe=P[mem[0]]["cwe"],size=len(mem),
            exact_normalized=exact,distinct_before_shapes=len(set(H[m] for m in mem)),distinct_after_shapes=len(set(AH[m] for m in mem)),distinct_before_with_strings=len(set(L2[m] for m in mem)),
            min_link_sim=round(min(sims),3) if sims else None,rules=sorted(set(P[m]["opengrep_rule"] for m in mem)),
            keep=[P[m]["id"] for m in mem if decision[m]=="keep"],drop=[P[m]["id"] for m in mem if decision[m]=="drop"]))
    return clusters,decision,SH
if __name__=="__main__":
    a=sys.argv; P=[json.loads(l) for l in open(a[1])]
    thr=float(a[a.index("--thr")+1]) if "--thr" in a else 0.85; keep=int(a[a.index("--keep")+1]) if "--keep" in a else 2
    out=a[a.index("--out")+1] if "--out" in a else "data/gold-near-dup-report.json"
    cl,dec,_=cluster(P,thr,keep)
    drops=[P[i]["id"] for i,d in dec.items() if d=="drop"]
    rep=dict(input=a[1],n_pairs=len(P),criteria=dict(normalization="strip comments; string literals->S; numbers->N; non-keyword identifiers->ID; whitespace ignored (token stream)",
        scope="clusters only within same (lang,cwe)",link="identical normalized before OR Jaccard(4-gram token shingles)>=%s; single-linkage union-find"%thr,
        keep_policy="cluster with a single before shape, single after shape AND single string-preserving shape: keep 1; otherwise: keep up to %d, prefer non-template sources (v0.1/mk/sam over bill), then distinct normalized-after (fix diversity), then distinct string-preserving before (L2)"%keep),
        n_clusters=len(cl),pairs_in_clusters=sum(c["size"] for c in cl),n_drop=len(drops),n_keep=len(P)-len(drops),
        by_source_drop=dict(collections.Counter(re.sub(r'-\d+$','',i).rsplit('-',2)[0] if '-bill-' in i else i.rsplit('-',1)[0] for i in drops)),
        clusters=sorted(cl,key=lambda c:-c["size"]),drop_ids=sorted(drops))
    json.dump(rep,open(out,"w"),indent=1,ensure_ascii=False)
    print(f"{len(cl)} clusters, {rep['pairs_in_clusters']} pairs in clusters, drop {len(drops)}, keep {rep['n_keep']}")
