# py/js/ts rules audit (pattern-only vs taint)

Source: rules/cylab.{python,javascript,typescript}.*.yaml

| rule file | mode |
|---|---|
| cylab.python.assert-auth.yaml | pattern-only |
| cylab.python.command-injection.yaml | **taint** (2026-10-27) |
| cylab.python.eval-exec-input.yaml | pattern-only |
| cylab.python.flask-debug.yaml | pattern-only |
| cylab.python.flask-unsafe-html.yaml | **taint** (2026-10-27) |
| cylab.python.hardcoded-secret.yaml | pattern-only |
| cylab.python.insecure-deserialization.yaml | pattern-only |
| cylab.python.log-secret.yaml | pattern-only |
| cylab.python.log-sensitive.yaml | pattern-only |
| cylab.python.md5-password.yaml | pattern-only |
| cylab.python.open-join-user.yaml | **taint** (2026-10-27) |
| cylab.python.os-system.yaml | **taint** (2026-10-27) |
| cylab.python.path-join-user.yaml | **taint** (2026-10-27) |
| cylab.python.path-traversal.yaml | **taint** (2026-10-27) |
| cylab.python.pickle-loads.yaml | pattern-only |
| cylab.python.requests-from-request.yaml | pattern-only |
| cylab.python.requests-url-user.yaml | pattern-only |
| cylab.python.sql-format.yaml | pattern-only |
| cylab.python.sql-injection.yaml | **taint** (2026-10-27) |
| cylab.python.sqli-fstring-execute.yaml | **taint** (2026-10-27) |
| cylab.python.ssl-verify-false.yaml | pattern-only |
| cylab.python.ssrf.yaml | pattern-only |
| cylab.python.stdlib-xml-parse.yaml | pattern-only |
| cylab.python.subprocess-shell-true.yaml | **taint** (2026-10-27) |
| cylab.python.tar-zip-extractall.yaml | **taint** (2026-10-27) |
| cylab.python.template-string-user.yaml | **taint** (2026-10-27) |
| cylab.python.tls-verify-off.yaml | pattern-only |
| cylab.python.unsafe-yaml-pickle.yaml | pattern-only |
| cylab.python.weak-cipher-mode.yaml | pattern-only |
| cylab.python.weak-hash.yaml | pattern-only |
| cylab.python.xml-xxe.yaml | pattern-only |
| cylab.javascript.child-exec.yaml | **taint** (2026-10-27) |
| cylab.javascript.command-injection.yaml | **taint** (2026-10-27) |
| cylab.javascript.cors-star.yaml | pattern-only |
| cylab.javascript.disable-tls.yaml | pattern-only |
| cylab.javascript.dom-sink-html.yaml | **taint** (2026-10-27) |
| cylab.javascript.dynamic-code-function.yaml | pattern-only |
| cylab.javascript.eval-user.yaml | pattern-only |
| cylab.javascript.exec-template.yaml | **taint** (2026-10-27) |
| cylab.javascript.express-file-param.yaml | **taint** (2026-10-27) |
| cylab.javascript.hardcoded-config-secret.yaml | pattern-only |
| cylab.javascript.hardcoded-jwt.yaml | pattern-only |
| cylab.javascript.hardcoded-secret.yaml | pattern-only |
| cylab.javascript.http-client-user-url.yaml | pattern-only |
| cylab.javascript.innerhtml-user.yaml | **taint** (2026-10-27) |
| cylab.javascript.mass-assign-merge.yaml | pattern-only |
| cylab.javascript.merge-proto.yaml | pattern-only |
| cylab.javascript.path-join-user.yaml | **taint** (2026-10-27) |
| cylab.javascript.path-traversal.yaml | **taint** (2026-10-27) |
| cylab.javascript.react-href.yaml | pattern-only |
| cylab.javascript.redirect-user.yaml | pattern-only |
| cylab.javascript.regexp-user-input.yaml | pattern-only |
| cylab.javascript.res-send-reflect.yaml | **taint** (2026-10-27) |
| cylab.javascript.sql-concat.yaml | **taint** (2026-10-27) |
| cylab.javascript.sql-injection.yaml | **taint** (2026-10-27) |
| cylab.javascript.sql-template-literal.yaml | **taint** (2026-10-27) |
| cylab.javascript.ssrf.yaml | pattern-only |
| cylab.javascript.weak-hash-createhash.yaml | pattern-only |
| cylab.javascript.weak-hash.yaml | pattern-only |
| cylab.javascript.xss-innerhtml.yaml | **taint** (2026-10-27) |
| cylab.typescript.angular-bypass-sanitizer.yaml | **taint** (2026-10-27) |
| cylab.typescript.any-req-body.yaml | pattern-only |
| cylab.typescript.client-location-redirect.yaml | pattern-only |
| cylab.typescript.cookie-insecure-flags.yaml | pattern-only |
| cylab.typescript.cors-wildcard-credentials.yaml | pattern-only |
| cylab.typescript.hardcoded-credential.yaml | pattern-only |
| cylab.typescript.innerhtml-assign.yaml | **taint** (2026-10-27) |
| cylab.typescript.insecure-randomness.yaml | pattern-only |
| cylab.typescript.jwt-decode-no-verify.yaml | pattern-only |
| cylab.typescript.math-random-token.yaml | pattern-only |
| cylab.typescript.open-redirect.yaml | pattern-only |
| cylab.typescript.orm-raw-unsafe.yaml | **taint** (2026-10-27) |
| cylab.typescript.readfile-template-path.yaml | **taint** (2026-10-27) |
| cylab.typescript.sql-injection.yaml | **taint** (2026-10-27) |
| cylab.typescript.sql-template-query.yaml | **taint** (2026-10-27) |
| cylab.typescript.unsafe-unserialize.yaml | pattern-only |
| cylab.typescript.xss-dangerously-set.yaml | pattern-only |


**Summary (updated 2026-10-27):** 30/77 py/js/ts rules now `mode: taint` (CWE-89/78/79/22). 47 still pattern-only. typescript.xss-dangerously-set stays pattern-only: gate writes .ts and JSX doesn't parse there. Other remaining rules (hardcoded secrets, weak hash/cipher, randomness, TLS, debug flags, CORS, cookies) are config/literal checks where taint doesn't fit; pattern is the right mode. Taint candidates for later: CWE-918 (ssrf/requests-*), CWE-502 (deserialization), CWE-95/94 (eval), CWE-601 (redirect). See gold_taint_progress.json.
