-- Modulo seguros: rotinas de consulta e manutencao de apolices
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS seguros;

CREATE TABLE IF NOT EXISTS seguros.apolices (
    apolice_id      BIGSERIAL PRIMARY KEY,
    segurado_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    premio      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_apolices_segurado_id ON seguros.apolices (segurado_id, criado_em DESC);

CREATE OR REPLACE FUNCTION seguros.fn_touch_apolices() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION seguros.fn_resumo_segurado(p_segurado BIGINT)
RETURNS TABLE (qtd BIGINT, premio_total NUMERIC)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT count(*), coalesce(sum(premio), 0)
      FROM seguros.apolices
     WHERE segurado_id = p_segurado
       AND status <> 'CANCELADA';
$$;

ALTER FUNCTION seguros.fn_resumo_segurado(BIGINT) OWNER TO seguros_owner;
REVOKE ALL ON FUNCTION seguros.fn_resumo_segurado(BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION seguros.fn_resumo_segurado(BIGINT) TO portal_corretor;
