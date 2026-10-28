"""Patch rules-taint/ (generated via scripts/gen_taint_rules.build) with gold fixes for py/js/ts:
- py CWE-22: drop send_from_directory sink (it's the safe fix); add guard sanitizers (startswith/commonpath by-side-effect)
- js/ts CWE-22: add unlink sinks; guard sanitizers ($X.startsWith, $RE.test($X) by-side-effect)
- js/ts CWE-79: JSX {__html: $X} sink; bypassSecurityTrust* sink
- js/ts CWE-89: allowlist ternary ($S.has(..) ? ..: ..) sanitizer"""
import yaml,glob,os
D=os.path.join(os.path.dirname(os.path.abspath(__file__)),'rules-taint')
def fv(p,mv='$X',se=True):
    d={'patterns':[{'pattern':p},{'focus-metavariable':mv}]}
    if se: d['by-side-effect']=True
    return d
for f in glob.glob(D+'/*.yaml'):
    y=yaml.safe_load(open(f)); r=y['rules'][0]; c=r['metadata']['cwe']; l=r['languages'][0]
    S=r['pattern-sinks']; Z=r['pattern-sanitizers']
    if l=='python' and c=='CWE-22':
        S[:]=[s for s in S if 'send_from_directory' not in s['patterns'][0]['pattern']]
        Z+=[fv('str($X).startswith(...)'),fv('$X.startswith(...)'),fv('os.path.commonpath([$X, ...])'),fv('$X.is_relative_to(...)')]
    if l!='python' and c=='CWE-22':
        S+=[{'patterns':[{'pattern':'$FS.unlink($X, ...)'},{'focus-metavariable':'$X'}]},{'patterns':[{'pattern':'unlink($X, ...)'},{'focus-metavariable':'$X'}]}]
        Z+=[fv('$X.startsWith(...)'),fv('$RE.test($X)')]
    if l!='python' and c=='CWE-79':
        S+=[{'patterns':[{'pattern':'{__html: $X}'},{'focus-metavariable':'$X'}]},
            {'patterns':[{'pattern':'$S.$B($X)'},{'metavariable-regex':{'metavariable':'$B','regex':'^bypassSecurityTrust'}},{'focus-metavariable':'$X'}]}]
    if l!='python' and c=='CWE-89':
        Z+=[{'pattern':'$S.has($X) ? $A : $B'},{'pattern':'$S.includes($X) ? $A : $B'}]
    r['metadata']['gold']='taint-v1-sam'
    yaml.safe_dump(y,open(f,'w'),sort_keys=False,allow_unicode=True)

# Pass 2: parameter sources taint the *declaration* (focus-metavariable) instead of every use,
# so by-side-effect guards (regex.test / startsWith / commonpath) actually sanitize later uses.
EXCL={'metavariable-regex':{'metavariable':'$P','regex':'^(?!(res|resp|response|next|cb|callback|db|pool|conn|ds|knex|client|s|sanitizer)$)'}}
JS=['function $F(..., $P, ...) {...}','($P) => {...}','($P) => $E','(..., $P, ...) => {...}','(..., $P, ...) => $E','$M(..., $P, ...) {...}',
    'function $F(..., {..., $P, ...}, ...) {...}','({..., $P, ...}) => {...}','({..., $P, ...}) => $E',
    'function $F(..., {..., $P, ...}: $T, ...) {...}','({..., $P, ...}: $T) => {...}','({..., $P, ...}: $T) => $E']
for f in glob.glob(D+'/*.yaml'):
    y=yaml.safe_load(open(f)); r=y['rules'][0]; l=r['languages'][0]
    src=[s for s in r['pattern-sources'] if 'patterns' not in s]
    if l=='python':
        p={'patterns':[{'pattern':'def $F(..., $P, ...):\n  ...'},{'focus-metavariable':'$P'},{'metavariable-regex':{'metavariable':'$P','regex':'^(?!(self|cls|conn|db|cur|cursor|session)$)'}}]}
    else:
        p={'patterns':[{'pattern-either':[{'pattern':x} for x in JS]},{'focus-metavariable':'$P'},EXCL]}
    r['pattern-sources']=[p]+src
    yaml.safe_dump(y,open(f,'w'),sort_keys=False,allow_unicode=True)
