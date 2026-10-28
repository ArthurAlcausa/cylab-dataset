#!/usr/bin/env python3
"""Gera rules endurecidas cylab.<lang>.<slug>-gold (C/C++ estruturais; bash regex ancorada fora de comentario)."""
import os,yaml
H=os.path.dirname(os.path.abspath(__file__)); ROOT=os.path.dirname(os.path.dirname(H))
NC=r'(?m)^(?!\s*#)[^#\n]*?'   # bash: linha nao-comentario, antes de qualquer '#'
def E(*ps): return {"pattern-either":[{"pattern":p} for p in ps]}
R={
# ---- C
"c.access-then-open":{"pattern-either":[{"pattern":"if (<... access($P, $M) ...>) $S;\n...\nopen($P, ...);"},{"pattern":"if (<... access($P, $M) ...>) $S;\n...\nreturn open($P, ...);"},{"pattern":"if (<... access($P, $M) ...>) $S;\n...\nfopen($P, ...);"},{"pattern":"if (<... access($P, $M) ...>) { ... open($P, ...); ... }"},{"pattern":"if (<... access($P, $M) ...>) { ... fopen($P, ...); ... }"},{"pattern":"if (<... access($P, $M) ...>) $S;\n...\n$X = open($P, ...);"},{"pattern":"if (<... access($P, $M) ...>) $S;\n...\n$X = fopen($P, ...);"},{"pattern":"if (<... access($P, $M) ...>) $S;\n...\nreturn fopen($P, ...);"}]},
"c.buffer-overflow-strcpy":E("strcpy($D, $S)","gets($B)"),
"c.command-injection":{"patterns":[{"pattern":"system($CMD)"},{"pattern-not":'system("...")'}]},
"c.format-string":{"patterns":[{"pattern":"printf($X)"},{"pattern-not":'printf("...")'}]},
"c.gets-call":E("gets($B)"),
"c.insecure-tempname":E("tmpnam(...)","tempnam(...)","mktemp(...)"),
"c.libc-rand-key":E("rand()","random()","drand48()"),
"c.malloc-mul-overflow":E("malloc($N * sizeof($T))","malloc(sizeof($T) * $N)"),
"c.memcpy-len-from-input":{"patterns":[{"pattern-either":[{"pattern":"memcpy($D, $S, $R->$F)"},{"pattern":"memcpy($D, $S, $R.$F)"}]},{"metavariable-regex":{"metavariable":"$F","regex":"^(len|tamanho|size)$"}}]},
"c.printf-nonliteral":{"patterns":[{"pattern-either":[{"pattern":"printf($X)"},{"pattern":"fprintf($F, $X)"},{"pattern":"syslog($P, $X)"}]},{"pattern-not":'printf("...")'},{"pattern-not":'fprintf($F, "...")'},{"pattern-not":'syslog($P, "...")'}]},
"c.scanf-unbounded-s":{"patterns":[{"pattern-either":[{"pattern":"scanf(...)"},{"pattern":"fscanf(...)"},{"pattern":"sscanf(...)"}]},{"pattern-regex":r'scanf\s*\([^;]*"[^"]*%s'}]},
"c.sprintf-unbounded":E("sprintf(...)","vsprintf(...)"),
"c.strcpy-strcat":E("strcpy($D, $S)","strcat($D, $S)"),
"c.system-popen":E("system($C)","popen($C, $M)"),
"c.world-writable-mode":{"patterns":[{"pattern-either":[{"pattern":"chmod($P, $M)"},{"pattern":"open($P, $FL, $M)"},{"pattern":"creat($P, $M)"},{"pattern":"mkdir($P, $M)"}]},{"metavariable-regex":{"metavariable":"$M","regex":"^0?(777|666)$"}}]},
# ---- C++
"cpp.cstr-copy-unbounded":E("strcpy($D, $S)","strcat($D, $S)","sprintf(...)","std::strcpy($D, $S)","std::strcat($D, $S)","std::sprintf(...)"),
"cpp.dangling-cstr":{"pattern-regex":r'const\s+char\s*\*\s*\w+\s*=\s*\(?[\w:]+\([^;]*\)(\s*\+[^;]*\))?\.c_str\(\)'},
"cpp.fmt-cstr-sink":E("snprintf($B, $N, $S.c_str())","std::snprintf($B, $N, $S.c_str())","syslog($P, $S.c_str())"),
"cpp.gets":E("gets($B)"),
"cpp.hardcoded-key-literal":{"pattern-regex":r'(?im)^\s*(static\s+)?(constexpr\s+)?(const\s+)?(std::string|char\s*\*|char|auto)\s+(const\s+)?\w*(key|chave|senha|password|token|secret)\w*(\[\])?\s*=\s*"[^"]{6,}"\s*;'},  # parser cpp do Opengrep 1.32 nao casou declaracoes static; regex ancorada em declaracao
"cpp.ifstream-concat":E("std::ifstream $F($A + $B);","std::ifstream $F($A + $B, ...);"),
"cpp.memcpy-string-size":E("memcpy($D, $S, $X.size())","memcpy($D, $S, $X.length())","std::memcpy($D, $S, $X.size())","std::memcpy($D, $S, $X.length())"),
"cpp.new-array-mul":E("new $T[$A * $B]"),
"cpp.ofstream-concat-path":E("std::ofstream $F($A + $B);","std::ofstream $F($A + $B, ...);","fs::remove($A / $B)","fs::remove_all($A / $B)"),
"cpp.openssl-weak-algo":{"patterns":[{"pattern-either":[{"pattern":"$F()"},{"pattern":"MD5(...)"}]},{"metavariable-regex":{"metavariable":"$F","regex":"^(EVP_(des_\\w+|aes_\\d+_ecb|rc4|md5|sha1)|MD5)$"}}]},
"cpp.printf-cstr":{"patterns":[{"pattern-either":[{"pattern":"printf($X)"},{"pattern":"fprintf($F, $X)"},{"pattern":"std::printf($X)"}]},{"pattern-not":'printf("...")'},{"pattern-not":'fprintf($F, "...")'},{"pattern-not":'std::printf("...")'}]},
"cpp.rand-token":E("rand()","std::rand()"),
"cpp.sprintf":E("sprintf($B, $FMT, ...)"),
"cpp.std-system":E("system($C)","std::system($C)","popen($C, $M)"),
"cpp.strcpy":E("strcpy($D, $S)"),
"cpp.system":E("system($CMD)","std::system($CMD)"),
# ---- bash (parser generico fraco: regex restrita a linha nao-comentario)
"bash.chmod-world-writable":{"pattern-regex":NC+r'\bchmod\s+(-R\s+)?(0?777|0?666|a\+w|o\+w)\b'},
"bash.curl-pipe-shell":{"pattern-regex":NC+r'\bcurl\b[^|\n#]*\|\s*(sudo\s+)?(ba)?sh\b'},
"bash.download-pipe-shell":{"pattern-regex":NC+r'\b(curl|wget)\b[^|\n#]*\|\s*(sudo\s+)?(ba|z)?sh\b'},
"bash.eval-injection":{"pattern-regex":NC+r'\beval\s+["\']?[^\n#]*\$'},
"bash.eval-variable":{"pattern-regex":NC+r'\beval\s+["\']?[^\n#]*\$'},
"bash.hardcoded-secret-var":{"pattern-regex":r'(?im)^\s*(export\s+)?\w*(PASSWORD|PASSWD|SENHA|TOKEN|SECRET|API_KEY)\w*=["\']?[A-Za-z0-9_#!@%.\-]{6,}'},
"bash.password-on-cmdline":{"pattern-regex":NC+r'(\b(mysql|mysqldump|mysqladmin)\b[^\n#]*\s-p\S+|\bsshpass\s+-p\s*\S+)'},
"bash.predictable-tmp":{"pattern-regex":NC+r'>\s*/tmp/[\w.\-]*(\$\$|\$\{?\w+\}?)?[\w.\-]*(\s|$)'},
"bash.secret-echo-to-file":{"pattern-regex":NC+r'\becho\s+"?[\w=]*\$\{?\w*(TOKEN|SENHA|PASSWORD|SECRET|KEY)\w*\}?"?\s*>>?\s*\S+'},
"bash.sh-c-interpolated":{"pattern-regex":NC+r'\b(ba)?sh\s+-c\s+"[^"]*\$'},
"bash.source-remote-script":{"pattern-regex":NC+r'(\bsource|(^|;|\s)\.)\s+<\(\s*(curl|wget)\b'},
"bash.sudoers-nopasswd-all":{"pattern-regex":NC+r'NOPASSWD:\s*ALL\b'},
"bash.tls-insecure-flag":{"pattern-regex":NC+r'(\bcurl\b[^\n#]*(\s-k\b|\s--insecure\b)|\bwget\b[^\n#]*--no-check-certificate)'},
"bash.unquoted-rm-var":{"pattern-regex":NC+r'\brm\s+-\w*\s+\$\{?\w+\}?(/|\s|$)'},
}
LANG={"c":"c","cpp":"cpp","bash":"bash"}
for k,body in R.items():
    lang=k.split(".")[0]; rid=f"cylab.{k}-gold"
    orig=yaml.safe_load(open(f"{ROOT}/rules/cylab.{k}.yaml"))["rules"][0]
    r={"id":rid,"languages":[lang],"severity":orig.get("severity","ERROR"),"message":orig.get("message",rid)}
    if "metadata" in orig: r["metadata"]=orig["metadata"]
    r.update(body)
    txt=yaml.safe_dump({"rules":[r]},sort_keys=False,allow_unicode=True)
    for d in (f"{H}/rules",f"{ROOT}/rules"): open(f"{d}/{rid}.yaml","w").write(txt)
print(len(R),"gold rules")
