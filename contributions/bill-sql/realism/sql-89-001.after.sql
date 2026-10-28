-- Modulo vendas: rotinas de consulta e manutencao de pedidos
-- Mantido pelo time de dados; revisar com DBA antes de deploy.
CREATE SCHEMA IF NOT EXISTS vendas;

CREATE TABLE IF NOT EXISTS vendas.pedidos (
    pedido_id      BIGSERIAL PRIMARY KEY,
    cliente_id      BIGINT       NOT NULL,
    status        VARCHAR(20)  NOT NULL DEFAULT 'ABERTO',
    valor_total      NUMERIC(14,2) NOT NULL DEFAULT 0,
    criado_em     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    atualizado_em TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_pedidos_cliente_id ON vendas.pedidos (cliente_id, criado_em DESC);

CREATE OR REPLACE FUNCTION vendas.fn_touch_pedidos() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.atualizado_em := now();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION vendas.fn_buscar_pedidos(p_status TEXT, p_ordem TEXT)
RETURNS SETOF vendas.pedidos LANGUAGE plpgsql AS $$
BEGIN
    IF p_status IS NULL THEN
        RAISE EXCEPTION 'status obrigatorio';
    END IF;
    RETURN QUERY EXECUTE
        'SELECT * FROM vendas.pedidos WHERE status = $1 ORDER BY criado_em DESC'
        USING p_status;
END;
$$;
