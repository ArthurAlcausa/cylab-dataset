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

CREATE OR REPLACE FUNCTION suporte.fn_fechar_chamados(p_conta BIGINT)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_qtd INTEGER := 0;
BEGIN
    UPDATE suporte.chamados
       SET status = 'FECHADO', atualizado_em = now()
     WHERE conta_id = p_conta;
    GET DIAGNOSTICS v_qtd = ROW_COUNT;
    RAISE NOTICE 'chamados fechados: %', v_qtd;
    RETURN v_qtd;
END;
$$;
