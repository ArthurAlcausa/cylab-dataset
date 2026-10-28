# SQL injection rules — flow-pattern gate (Sam, 2026-10-27)
- 8 cylab.sql.* injection rules rewritten as `patterns` (pattern-either: direct concat sink + var-assigned-then-EXEC/PREPARE flow) + `pattern-not-regex` sanitizers (QUOTENAME, quote_*, DBMS_ASSERT, parameterized sp_executesql).
- True `mode: taint` impossible: Opengrep 1.32 has no SQL parser and rejects taint with generic.
- Gate: 26/26 pairs before≥1/after=0 (9 Markinho gold + 17 v0.3 DRAFT; baseline also 26/26).
- Originals: rules-sql-pattern-backup/. Per-pair: gate_report_sql_flow.json.
