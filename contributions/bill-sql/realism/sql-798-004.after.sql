-- Modulo financeiro: rotinas de consulta e manutencao de faturas
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS financeiro;

CREATE TABLE IF NOT EXISTS financeiro.faturas (
    fatura_id      BIGSERIAL PRIMARY KEY,
    empresa_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    valor_liquido      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_faturas_empresa_id ON financeiro.faturas (empresa_id, criado_em DESC);

CREATE OR REPLACE FUNCTION financeiro.fn_touch_faturas() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

CREATE EXTENSION IF NOT EXISTS postgres_fdw;

CREATE SERVER IF NOT EXISTS erp_legado
    FOREIGN DATA WRAPPER postgres_fdw
    OPTIONS (host 'erp-legado.interno', port '5432', dbname 'erp', sslmode 'verify-full');

/* Autenticacao por certificado cliente; nenhum segredo no DDL */
CREATE USER MAPPING IF NOT EXISTS FOR financeiro_app
    SERVER erp_legado
    OPTIONS (user 'leitura_fin', sslcert '/etc/pg/fdw/leitura_fin.crt', sslkey '/etc/pg/fdw/leitura_fin.key');

IMPORT FOREIGN SCHEMA public LIMIT TO (titulos_receber)
    FROM SERVER erp_legado INTO financeiro;
