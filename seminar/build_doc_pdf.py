#!/usr/bin/env python3
"""Converte seminar/DOC_ACADEMICO_BANCA.md em DOC_ACADEMICO_BANCA.pdf (python-markdown + latex2mathml + Chrome headless).
Uso: python3 seminar/build_doc_pdf.py"""
import os, re, html, subprocess, markdown
from latex2mathml.converter import convert as tex2mml
H = os.path.dirname(os.path.abspath(__file__))
SRC, OUT, TMP = os.path.join(H, "DOC_ACADEMICO_BANCA.md"), os.path.join(H, "DOC_ACADEMICO_BANCA.pdf"), os.path.join(H, ".doc_build.html")
md = open(SRC, encoding="utf-8").read()
# front matter YAML simples
fm, body = re.match(r"^---\n(.*?)\n---\n(.*)$", md, re.S).groups()
meta, key = {}, None
for ln in fm.splitlines():
    m = re.match(r'^(\w+):\s*(.*)$', ln)
    if m:
        key, v = m.groups(); meta[key] = v.strip().strip('"') if v.strip() else []
    elif ln.strip().startswith("- ") and key:
        meta[key].append(ln.strip()[2:].strip('"'))
inline = lambda t: re.sub(r"`([^`]+)`", r"<code>\1</code>", re.sub(r"\*([^*]+)\*", r"<em>\1</em>", html.escape(t, quote=False)))
# títulos não numerados, legendas e matemática
body = re.sub(r"^(#+ .*?) \{-\}\s*$", r"\1 {: .unnum }", body, flags=re.M)
body = re.sub(r"^: (.+)$", lambda m: "TCAP§" + m.group(1), body, flags=re.M)
maths = []
def keep_math(m):
    maths.append(tex2mml(m.group(1).strip(), display="block")); return f"\n\nMATH§{len(maths)-1}\n\n"
body = re.sub(r"\$\$(.+?)\$\$", keep_math, body, flags=re.S)
h = markdown.markdown(body, extensions=["tables", "fenced_code", "sane_lists", "attr_list"])
h = re.sub(r"<p>TCAP§(.*?)</p>", lambda m: f'<p class="tcap">{m.group(1)}</p>', h, flags=re.S)
h = re.sub(r"<p>MATH§(\d+)</p>", lambda m: f'<div class="math">{maths[int(m.group(1))]}</div>', h)
def fig(m):
    alt, src = html.unescape(m.group(1)), m.group(2)
    if src.endswith(".png") and os.path.isfile(os.path.join(H, src[:-4] + ".svg")): src = src[:-4] + ".svg"  # vetorial no PDF
    return f'<figure><img src="{src}"/><figcaption>{inline(alt)}</figcaption></figure>'
h = re.sub(r'<p><img alt="(.*?)" src="(.*?)" ?/?></p>', fig, h, flags=re.S)
h = re.sub(r"<del>(.*?)</del>", r"<s>\1</s>", h)
h = re.sub(r"~~(.+?)~~", r"<s>\1</s>", h)
authors = "".join(f"<div>{html.escape(a)}</div>" for a in meta.get("author", []))
title = f'''<section class="capa"><div class="kicker">Projeto Cylab · PUC-Campinas</div>
<h1 class="titulo">{html.escape(meta.get("title",""))}</h1><div class="sub">{html.escape(meta.get("subtitle",""))}</div>
<div class="autores">{authors}</div><div class="data">{html.escape(meta.get("date",""))}</div>
<div class="repo">Repositório público: https://github.com/ArthurAlcausa/cylab-dataset</div></section>'''
css = r"""
@page { size: A4; margin: 25mm 20mm 22mm 30mm;
  @bottom-right { content: counter(page); font: 10pt 'Liberation Serif', serif; color: #555; } }
@page :first { @bottom-right { content: none; } }
body { font-family: 'Liberation Serif', 'Times New Roman', serif; font-size: 12pt; line-height: 1.45; color: #111; text-align: justify; hyphens: auto; counter-reset: h1; }
.capa { height: 240mm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; text-align: left; }
.kicker { font-family: Lexend, sans-serif; color: #2E6B57; letter-spacing: .08em; text-transform: uppercase; font-size: 10pt; margin-bottom: 8mm; }
.titulo { counter-increment: none; text-transform: none; font-size: 22pt; line-height: 1.25; margin: 0 0 6mm; text-align: left; border-left: 5px solid #2E6B57; padding-left: 5mm; }
.titulo::before { content: none !important; }
.sub { font-size: 14pt; color: #2E6B57; margin-bottom: 18mm; }
.autores div { font-size: 12pt; } .data { margin-top: 10mm; } .repo { margin-top: 3mm; font-size: 10.5pt; color: #2E6B57; }
h1, h2, h3 { text-align: left; page-break-after: avoid; color: #1F2A27; }
h1 { font-size: 15pt; margin: 9mm 0 3mm; counter-increment: h1; counter-reset: h2; text-transform: uppercase; }
h1:not(.unnum)::before { content: counter(h1) " "; color: #2E6B57; }
h2 { font-size: 12.5pt; margin: 6mm 0 2mm; counter-increment: h2; }
h1.unnum + * h2::before, h2.unnum::before { content: none; }
h2:not(.unnum)::before { content: counter(h1) "." counter(h2) " "; color: #2E6B57; }
h1.unnum { counter-increment: none; text-align: center; }
p { margin: 0 0 2.6mm; orphans: 3; widows: 3; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 9.5pt; background: #F1EFEA; padding: 0 2px; border-radius: 2px; }
pre { background: #F5F3EF; border-left: 3px solid #2E6B57; padding: 3mm 4mm; font-size: 9pt; white-space: pre-wrap; page-break-inside: avoid; text-align: left; }
pre code { background: none; padding: 0; font-size: 9pt; }
table { border-collapse: collapse; width: 100%; font-size: 10pt; margin: 1mm 0 5mm; page-break-inside: avoid; line-height: 1.3; }
th, td { border-top: 1px solid #999; border-bottom: 1px solid #999; padding: 1.4mm 2mm; text-align: left; vertical-align: top; }
th { border-top: 1.5px solid #111; border-bottom: 1.5px solid #111; background: #F1EFEA; }
td[align=right], th[align=right] { text-align: right; }
.tcap { font-size: 10.5pt; text-align: left; margin: 4mm 0 1mm; font-weight: bold; page-break-after: avoid; }
figure { margin: 4mm 0 5mm; page-break-inside: avoid; text-align: center; }
figure img { width: 100%; border: 1px solid #D9D6CF; }
figcaption { font-size: 10pt; text-align: left; margin-top: 2mm; line-height: 1.35; }
.math { text-align: center; margin: 3mm 0 4mm; font-size: 13pt; }
math { font-family: 'Latin Modern Math', 'STIX Two Math', 'DejaVu Serif', serif; }
ul, ol { margin: 0 0 3mm; padding-left: 7mm; } li { margin-bottom: 1.2mm; }
s { color: #777; }
"""
doc = f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>{html.escape(meta.get("title",""))}</title><style>{css}</style></head><body>{title}{h}</body></html>'
open(TMP, "w", encoding="utf-8").write(doc)
subprocess.run(["google-chrome", "--headless=new", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer", "--run-all-compositor-stages-before-draw",
                "--virtual-time-budget=5000", f"--print-to-pdf={OUT}", "file://" + TMP], check=True, capture_output=True)
os.remove(TMP); print("PDF", OUT)
