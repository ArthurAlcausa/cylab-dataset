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

CREATE OR REPLACE FUNCTION suporte.fn_buscar_chamados(p_texto TEXT, p_limite INT DEFAULT 50)
RETURNS SETOF suporte.chamados LANGUAGE plpgsql STABLE AS $$
BEGIN
    IF p_limite > 500 THEN
        p_limite := 500;
    END IF;
    RETURN QUERY EXECUTE format(
        'SELECT * FROM suporte.chamados WHERE titulo ILIKE ''%%%s%%'' ORDER BY criado_em DESC LIMIT %s',
        p_texto, p_limite);
END;
$$;
