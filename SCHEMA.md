# Schema (JSONL, uma linha por par, chaves exatamente nesta ordem)
| campo | regra |
|---|---|
| id | `cylab-v0.1-NNNN`, único |
| lang | python, javascript, typescript, java, php, csharp, c, cpp, sql ou bash |
| cwe | `CWE-<n>` |
| source | `sintetico-cylab https://cwe.mitre.org/data/definitions/<n>.html` |
| license | `CC-BY-4.0` |
| opengrep_rule | `cylab.<lang>.<slug>`, nunca nulo; precisa existir `rules/<id>.yaml` |
| before | trecho vulnerável completo |
| after | trecho corrigido completo (não é um diff) |
| explanation_pt | explicação em português do Brasil citando a CWE |
| split | `train` ou `holdout` (mínimo de 4 holdout) |
