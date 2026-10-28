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

CREATE OR REPLACE FUNCTION vendas.fn_aprovar_pedido(p_pedido BIGINT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE pedidos SET status = 'APROVADO' WHERE pedido_id = p_pedido;
    INSERT INTO pedidos_aprovacao (pedido_id, aprovado_por, aprovado_em)
    VALUES (p_pedido, session_user, now());
END;
$$;

REVOKE ALL ON FUNCTION vendas.fn_aprovar_pedido(BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vendas.fn_aprovar_pedido(BIGINT) TO vendas_app;
