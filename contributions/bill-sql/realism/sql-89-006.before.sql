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

CREATE OR REPLACE FUNCTION compras.fn_arquivar_contratos(p_tabela_destino TEXT, p_fornecedor BIGINT)
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
    v_qtd INTEGER;
BEGIN
    EXECUTE 'INSERT INTO compras.' || p_tabela_destino
         || ' SELECT * FROM compras.contratos WHERE fornecedor_id = $1 AND status = ''ENCERRADO'''
      USING p_fornecedor;
    GET DIAGNOSTICS v_qtd = ROW_COUNT;
    DELETE FROM compras.contratos
     WHERE fornecedor_id = p_fornecedor AND status = 'ENCERRADO';
    RETURN v_qtd;
END;
$$;
