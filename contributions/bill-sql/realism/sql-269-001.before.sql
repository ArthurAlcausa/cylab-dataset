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

CREATE ROLE vendas_app NOLOGIN;
CREATE ROLE vendas_bi  NOLOGIN;

CREATE OR REPLACE VIEW vendas.vw_pedidos_mes AS
SELECT date_trunc('month', criado_em) AS mes, count(*) AS qtd, sum(valor_total) AS total
  FROM vendas.pedidos
 GROUP BY 1;

GRANT USAGE ON SCHEMA vendas TO vendas_app, vendas_bi;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA vendas TO PUBLIC;
GRANT SELECT ON vendas.vw_pedidos_mes TO vendas_bi;
