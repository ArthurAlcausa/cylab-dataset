#!/usr/bin/env python3
"""Gera seminar/assets/cylab-arquitetura.svg (e .png via Chrome headless).
Logos: simple-icons (CC0, https://simpleicons.org, v16.36.0) em assets/logos/; marca Opengrep extraída do banner oficial
(github.com/opengrep/opengrep/images). Marcas pertencem aos respectivos titulares; uso apenas identificativo.
Uso: python3 seminar/assets/build_arquitetura.py [--png]"""
import os, re, sys, subprocess, html
H = os.path.dirname(os.path.abspath(__file__)); L = os.path.join(H, "logos")
W, HH = 1600, 1040
PAPER, FOREST, CHAR, GRAY, MINT, TEAL = "#F5F3EF", "#2E6B57", "#1F2A27", "#D9D6CF", "#E3EEE8", "#3E8E7E"
FT, FB, FM = "Lexend, Poppins, 'DejaVu Sans', sans-serif", "Poppins, 'DejaVu Sans', sans-serif", "'DejaVu Sans Mono', monospace"

def icon(name, x, y, size, color):
    s = open(os.path.join(L, name + ".svg")).read()
    vb = re.search(r'viewBox="([^"]+)"', s).group(1)
    ds = re.findall(r'<path d="([^"]+)"', s)
    if name == "opengrep-mark":
        body = "".join(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="3.6"/>' for d in ds)
    else:
        body = "".join(f'<path d="{d}" fill="{color}"/>' for d in ds)
    return f'<svg x="{x}" y="{y}" width="{size}" height="{size}" viewBox="{vb}">{body}</svg>'

def text(x, y, lines, size=16, fill=CHAR, weight=400, font=FB, anchor="middle", lh=1.3, italic=False):
    if isinstance(lines, str): lines = [lines]
    st = ' font-style="italic"' if italic else ""
    out = [f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>']
    for i, ln in enumerate(lines):
        out.append(f'<tspan x="{x}" dy="{0 if i == 0 else size*lh:.1f}">{ln}</tspan>')
    out.append("</text>"); return "".join(out)

E = []  # elementos
a = E.append
a(f'<rect width="{W}" height="{HH}" fill="{PAPER}"/>')
# cabeçalho
a(text(50, 52, "CYLAB · PUC-CAMPINAS · ARQUITETURA DO SISTEMA", 15, FOREST, 600, FT, "start"))
a(text(50, 92, "Pipeline híbrido: o motor determinístico detecta, o LLM local explica e corrige, o mesmo motor confere", 26, CHAR, 600, FT, "start"))
a(f'<rect x="50" y="106" width="120" height="5" rx="2" fill="{FOREST}"/>')

# fronteira "máquina do usuário"
a(f'<rect x="30" y="138" width="1540" height="440" rx="22" fill="#FFFFFF" fill-opacity="0.55" stroke="{FOREST}" stroke-width="2" stroke-dasharray="10 7"/>')
a(f'<rect x="54" y="126" width="520" height="26" rx="13" fill="{FOREST}"/>')
a(text(314, 145, "MÁQUINA DO USUÁRIO · 100% LOCAL · o código não sai daqui", 14, "#FFFFFF", 600, FT))

# nós do pipeline
NX0, NW, GAP, NY, NH = 50, 180, 40, 214, 214
def nx(i): return NX0 + i * (NW + GAP)
nodes = [
    dict(t=["Código-fonte"], s=["do desenvolvedor", "10 linguagens"], fill="#FFFFFF", fg=CHAR, stroke=GRAY, icons=[("python", "#3776AB"), ("javascript", "#C9A800"), ("openjdk", CHAR), ("cplusplus", "#00599C")]),
    dict(t=["Opengrep"], s=["regras Cylab / CWE", "rules-gold/: taint,", "estrutural, regex"], fill=CHAR, fg="#FFFFFF", stroke=CHAR, logo=("opengrep-mark", "#7FD1B9")),
    dict(t=["Achado"], s=["{regra, CWE, trecho}", "ex.: cylab.python.", "sqli-fstring-execute", "· CWE-89"], fill="#ECEAE4", fg=CHAR, stroke=GRAY, mono=True),
    dict(t=["LLM local"], s=["via Ollama", "Qwen2.5-Coder-14B", "+ LoRA/QLoRA"], fill=FOREST, fg="#FFFFFF", stroke=FOREST, logo=("ollama", "#FFFFFF"), tag="PLANEJADO"),
    dict(t=["Explicação", "pt-BR + patch"], s=["cita a CWE;", "trecho reescrito", "completo (after)"], fill=MINT, fg=CHAR, stroke=FOREST),
    dict(t=["Re-scan", "Opengrep (gate)"], s=["mesma regra", "no trecho corrigido"], fill=CHAR, fg="#FFFFFF", stroke=CHAR, logo=("opengrep-mark", "#7FD1B9")),
    dict(t=["Aceite"], s=["patch entregue", "ao desenvolvedor", "com explicação"], fill="#FFFFFF", fg=CHAR, stroke=FOREST, check=True),
]
# rótulos de fase
for (i0, i1, lab, col) in [(1, 1, "1 · DETECTA", CHAR), (3, 4, "2 · EXPLICA E CORRIGE", FOREST), (5, 5, "3 · CONFERE", CHAR)]:
    x0, x1 = nx(i0), nx(i1) + NW
    a(f'<path d="M{x0+6} 196 V186 H{x1-6} V196" fill="none" stroke="{col}" stroke-width="2"/>')
    a(text((x0 + x1) / 2, 178, lab, 14, col, 700, FT))
for i, n in enumerate(nodes):
    x = nx(i)
    a(f'<rect x="{x}" y="{NY}" width="{NW}" height="{NH}" rx="16" fill="{n["fill"]}" stroke="{n["stroke"]}" stroke-width="2"/>')
    # número do passo
    dark = n["fill"] in (CHAR, FOREST)
    a(f'<circle cx="{x+22}" cy="{NY+22}" r="13" fill="{"#FFFFFF" if dark else FOREST}"/>')
    a(text(x + 22, NY + 27, str(i + 1), 14, FOREST if dark else "#FFFFFF", 700, FT))
    cy = NY + 26
    if "logo" in n:
        a(icon(n["logo"][0], x + NW/2 - 22, NY + 14, 44, n["logo"][1]))
    elif "icons" in n:
        k = len(n["icons"]); sz = 26; x0 = x + 46
        for j, (nm, col) in enumerate(n["icons"]):
            a(icon(nm, x0 + j*(sz+6), NY + 24, sz, col))
    elif n.get("check"):
        a(f'<circle cx="{x+NW/2}" cy="{NY+36}" r="22" fill="{FOREST}"/><path d="M{x+NW/2-10} {NY+37} l7 7 l13 -15" fill="none" stroke="#FFFFFF" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>')
    else:
        a(f'<rect x="{x+NW/2-17}" y="{NY+16}" width="34" height="40" rx="4" fill="#FFFFFF" stroke="{CHAR}" stroke-width="2"/>'
          f'<path d="M{x+NW/2-10} {NY+28} h20 M{x+NW/2-10} {NY+36} h20 M{x+NW/2-10} {NY+44} h12" stroke="#B8442E" stroke-width="2.5" stroke-linecap="round"/>')
    ty = NY + 88
    a(text(x + NW/2, ty, n["t"], 20, n["fg"], 600, FT, lh=1.15))
    sy = ty + 20*1.15*(len(n["t"])-1) + 28
    a(text(x + NW/2, sy, n["s"], 13.5 if n.get("mono") else 14.5, "#D7E6DF" if dark else "#4A5652", 400, FM if n.get("mono") else FB, lh=1.3))
    if n.get("tag"):
        a(f'<rect x="{x+NW/2-46}" y="{NY+NH-6}" width="92" height="22" rx="11" fill="#E9B44C"/>')
        a(text(x + NW/2, NY + NH + 10, n["tag"], 12, CHAR, 700, FT))
    if i < len(nodes) - 1:
        ax = x + NW + 4
        a(f'<path d="M{ax} {NY+NH/2} H{ax+GAP-12}" stroke="{FOREST}" stroke-width="3.5"/><path d="M{ax+GAP-14} {NY+NH/2-8} L{ax+GAP-6} {NY+NH/2} L{ax+GAP-14} {NY+NH/2+8} Z" fill="{FOREST}"/>')

# fórmula do gate (abaixo do nó 6) e laço de rejeição (6 -> 4)
g6, g4 = nx(5), nx(3)
a(f'<rect x="{g6-50}" y="{NY+NH+26}" width="{NW+100}" height="58" rx="10" fill="#FFFFFF" stroke="{CHAR}" stroke-width="1.5"/>')
a(text(g6 + NW/2, NY + NH + 50, "aceite ⇔ achados(before) ≥ 1", 14, CHAR, 600, FM))
a(text(g6 + NW/2, NY + NH + 72, "∧ achados(after) = 0", 14, CHAR, 600, FM))
ly = NY + NH + 108
a(f'<path d="M{g6+NW/2} {NY+NH+84} V{ly} H{g4+NW/2} V{NY+NH+22}" fill="none" stroke="#B8442E" stroke-width="2.5" stroke-dasharray="7 5"/>')
a(f'<path d="M{g4+NW/2-8} {NY+NH+30} L{g4+NW/2} {NY+NH+18} L{g4+NW/2+8} {NY+NH+30} Z" fill="#B8442E"/>')
a(text(g4 + NW/2 + 16, ly - 8, "reprovado no gate → nova tentativa do LLM ou descarte", 13.5, "#B8442E", 600, FB, "start"))
a(text(g4 + NW/2 + 16, ly + 20, "o LLM nunca decide o que é vulnerável", 13.5, "#B8442E", 400, FB, "start", italic=True))

# faixa de responsabilidades (dentro da fronteira, à esquerda)
a(f'<rect x="50" y="{NY+NH+30}" width="590" height="94" rx="12" fill="#FFFFFF" stroke="{GRAY}" stroke-width="1.5"/>')
a(text(70, NY + NH + 56, "Divisão de responsabilidades", 15, FOREST, 700, FT, "start"))
for j, (c, t) in enumerate([(CHAR, "Opengrep: detecção e verificação determinísticas, auditáveis regra a regra"),
                            (FOREST, "LLM: só linguagem e reescrita; recebe o achado como contexto"),
                            ("#E9B44C", "Nesta entrega: explicação e patch vêm do dataset; nenhum LLM rodando")]):
    yy = NY + NH + 80 + j * 20
    a(f'<rect x="70" y="{yy-11}" width="12" height="12" rx="3" fill="{c}"/>')
    a(text(90, yy, t, 13.5, CHAR, 400, FB, "start"))

# painel do dataset
DY = 604
a(f'<rect x="30" y="{DY}" width="1540" height="196" rx="18" fill="{CHAR}"/>')
a(text(60, DY + 38, "DATASET OURO · v0.4-gold", 15, "#7FD1B9", 700, FT, "start"))
a(text(60, DY + 64, "treina e avalia o componente de linguagem (o passo 4)", 14, "#C9D6D1", 400, FB, "start"))
steps = [("2.191", "v0.2 comercial", "10 linguagens"), ("476", "v0.3-gold", "após quase-duplicatas"), ("+100", "buffer de realismo", "mediana de 35 linhas"), ("576", "v0.4-gold", "gate 576/576")]
filters = ["Jaccard 4-gramas ≥ 0,85 · estrato lang+CWE", "onda v0.4 · 4 frentes", "re-scan rules-gold"]
bx0, bw, bg = 60, 190, 160
for j, (num, l1, l2) in enumerate(steps):
    x = bx0 + j * (bw + bg); last = j == len(steps) - 1
    a(f'<rect x="{x}" y="{DY+82}" width="{bw}" height="96" rx="12" fill="{FOREST if last else "#2C3A36"}" stroke="{"#7FD1B9" if last else "#41524D"}" stroke-width="2"/>')
    a(text(x + bw/2, DY + 122, num, 32, "#FFFFFF", 700, FT))
    a(text(x + bw/2, DY + 146, l1, 14.5, "#FFFFFF", 600, FB))
    a(text(x + bw/2, DY + 166, l2, 13, "#C9D6D1", 400, FB))
    if not last:
        ax = x + bw + 8
        a(f'<path d="M{ax} {DY+130} H{ax+bg-22}" stroke="#7FD1B9" stroke-width="3"/><path d="M{ax+bg-24} {DY+122} L{ax+bg-14} {DY+130} L{ax+bg-24} {DY+138} Z" fill="#7FD1B9"/>')
        a(text(ax + (bg-14)/2, DY + 118, filters[j].split(" · ")[0], 11.5, "#C9D6D1", 400, FB))
        if " · " in filters[j]: a(text(ax + (bg-14)/2, DY + 152, filters[j].split(" · ")[1], 11.5, "#C9D6D1", 400, FB))
# estatísticas à direita
sx = 1340
a(f'<path d="M{sx-20} {DY+30} V{DY+170}" stroke="#41524D" stroke-width="2"/>')
a(text(sx, DY + 50, ["489 treino · 87 holdout", "10 linguagens · 43 CWEs", "178 regras · CC-BY-4.0", "pares escritos do zero", "sem modelo treinado"], 14.5, "#FFFFFF", 400, FB, "start", 1.45))
# seta dataset -> LLM (ajuste fino planejado)
lx = nx(3) + NW/2 - 50
a(f'<path d="M{lx} {DY-2} V{NY+NH+20}" stroke="#E9B44C" stroke-width="2.5" stroke-dasharray="6 5" fill="none"/>')
a(f'<path d="M{lx-7} {NY+NH+30} L{lx} {NY+NH+18} L{lx+7} {NY+NH+30} Z" fill="#E9B44C"/>')
a(text(lx + 12, DY + 24, "ajuste fino LoRA/QLoRA · planejado", 13, "#E9B44C", 600, FB, "start"))

# faixa de stack
SY = 826
a(text(50, SY + 20, "STACK", 15, FOREST, 700, FT, "start"))
langs = [("python", "#3776AB", "Python"), ("javascript", "#C9A800", "JavaScript"), ("typescript", "#3178C6", "TypeScript"), ("openjdk", CHAR, "Java"),
         ("php", "#777BB4", "PHP"), ("dotnet", "#512BD4", "C# / .NET"), ("c", "#5C6BC0", "C"), ("cplusplus", "#00599C", "C++"),
         ("postgresql", "#4169E1", "SQL · PostgreSQL"), ("gnubash", "#4EAA25", "Bash")]
tools = [("opengrep-mark", FOREST, "Opengrep 1.32", "detecção + gate"), ("ollama", CHAR, "Ollama", "planejado"), ("python", "#3776AB", "Python", "scripts do gate"),
         ("visualstudiocode", "#007ACC", "VS Code", "CLI/extensão planejadas")]
a(text(50, SY + 50, "Linguagens do dataset", 13, "#4A5652", 500, FB, "start"))
x = 50
for j, (nm, col, lab) in enumerate(langs):
    cw = 58 + int(len(lab) * 8.6); y = SY + 62
    a(f'<rect x="{x}" y="{y}" width="{cw}" height="44" rx="22" fill="#FFFFFF" stroke="{GRAY}" stroke-width="1.5"/>')
    a(icon(nm, x + 13, y + 10, 24, col))
    a(text(x + 45, y + 28, lab, 15, CHAR, 500, FB, "start"))
    x += cw + 10
a(text(50, SY + 132, "Ferramentas", 13, "#4A5652", 500, FB, "start"))
x = 50
for j, (nm, col, lab, sub) in enumerate(tools):
    tw = 66 + int(len(lab) * 9.4 + len(sub) * 7.6); y = SY + 142
    a(f'<rect x="{x}" y="{y}" width="{tw}" height="44" rx="22" fill="#FFFFFF" stroke="{FOREST if "planej" not in sub else "#E9B44C"}" stroke-width="1.8"/>')
    a(icon(nm, x + 14, y + 9, 26, col))
    a(text(x + 50, y + 28, f'<tspan font-weight="600">{lab}</tspan><tspan fill="#4A5652" font-size="13"> · {sub}</tspan>', 15, CHAR, 400, FB, "start"))
    x += tw + 12
a(text(1550, SY + 168, ["github.com/ArthurAlcausa/cylab-dataset"], 15, FOREST, 600, FT, "end"))
a(text(1550, SY + 188, "logos: simple-icons (CC0) e Opengrep; marcas de seus titulares", 11, "#7A8480", 400, FB, "end"))

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{HH}" viewBox="0 0 {W} {HH}" role="img" aria-label="Arquitetura do Cylab">\n'
       '<!-- Cylab — arquitetura híbrida. Logos: simple-icons v16.36.0 (CC0, simpleicons.org); marca Opengrep de github.com/opengrep/opengrep (LGPL-2.1). Gerado por seminar/assets/build_arquitetura.py -->\n'
       '<title>Cylab — pipeline híbrido Opengrep + LLM local + gate</title>\n' + "\n".join(E) + "\n</svg>\n")
out = os.path.join(H, "cylab-arquitetura.svg"); open(out, "w").write(svg); print("SVG", out, len(svg))
if "--png" in sys.argv:
    page = os.path.join("/tmp", "cylab-arq.html")
    open(page, "w").write(f'<html><body style="margin:0">{svg}</body></html>')
    png = os.path.join(H, "cylab-arquitetura.png")
    subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", f"--window-size={W},{HH}",
                    "--force-device-scale-factor=2", f"--screenshot={png}", "file://" + page], check=True, capture_output=True)
    print("PNG", png)
