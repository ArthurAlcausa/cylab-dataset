-- Modulo suporte: rotinas de consulta e manutencao de chamados
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS suporte;

CREATE TABLE IF NOT EXISTS suporte.chamados (
    chamado_id      BIGSERIAL PRIMARY KEY,
    conta_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    sla_horas      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_chamados_conta_id ON suporte.chamados (conta_id, criado_em DESC);

CREATE OR REPLACE FUNCTION suporte.fn_touch_chamados() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS suporte.agentes (
    agente_id    BIGSERIAL PRIMARY KEY,
    email        CITEXT       NOT NULL UNIQUE,
    nome         VARCHAR(120) NOT NULL,
    hash_portal  TEXT         NOT NULL,
    ativo        BOOLEAN      NOT NULL DEFAULT true,
    ultimo_login TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION suporte.fn_validar_login(p_email TEXT, p_segredo TEXT)
RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM suporte.agentes
                    WHERE email = p_email AND hash_portal = crypt(p_segredo, hash_portal) AND ativo);
$$;
