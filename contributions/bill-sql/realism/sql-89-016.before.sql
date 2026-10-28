-- Modulo logistica: rotinas de consulta e manutencao de estoque_mov
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS logistica;

CREATE TABLE IF NOT EXISTS logistica.estoque_mov (
    mov_id      BIGSERIAL PRIMARY KEY,
    filial_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    quantidade      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_estoque_mov_filial_id ON logistica.estoque_mov (filial_id, criado_em DESC);

CREATE OR REPLACE FUNCTION logistica.fn_touch_estoque_mov() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION logistica.fn_saldo_por_coluna(p_coluna TEXT, p_filial BIGINT)
RETURNS NUMERIC LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_saldo NUMERIC;
BEGIN
    EXECUTE format('SELECT sum(%s) FROM logistica.estoque_mov WHERE filial_id = $1', p_coluna)
       INTO v_saldo
      USING p_filial;
    RETURN coalesce(v_saldo, 0);
END;
$$;
