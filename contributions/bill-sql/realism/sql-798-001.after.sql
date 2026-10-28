-- Modulo compras: rotinas de consulta e manutencao de contratos
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS compras;

CREATE TABLE IF NOT EXISTS compras.contratos (
    contrato_id      BIGSERIAL PRIMARY KEY,
    fornecedor_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    valor_mensal      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_contratos_fornecedor_id ON compras.contratos (fornecedor_id, criado_em DESC);

CREATE OR REPLACE FUNCTION compras.fn_touch_contratos() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

\set etl_pwd `cat /run/secrets/compras_etl_pwd`
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'compras_etl') THEN
        CREATE ROLE compras_etl LOGIN CONNECTION LIMIT 5;
    END IF;
END;
$$;
ALTER ROLE compras_etl PASSWORD :'etl_pwd';

GRANT USAGE ON SCHEMA compras TO compras_etl;
GRANT SELECT, INSERT ON compras.contratos TO compras_etl;
ALTER ROLE compras_etl SET statement_timeout = '15min';
