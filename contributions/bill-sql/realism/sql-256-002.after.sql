-- Modulo vendas (MySQL 8): procedures de relatorio de pedidos
CREATE TABLE IF NOT EXISTS pedidos (
    pedido_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    cliente_id   BIGINT UNSIGNED NOT NULL,
    status     VARCHAR(20) NOT NULL DEFAULT 'ABERTO',
    valor_total   DECIMAL(14,2) NOT NULL DEFAULT 0,
    criado_em  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pedido_id),
    KEY ix_cliente_id (cliente_id, criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auditoria_relatorio (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    usuario    VARCHAR(64) NOT NULL,
    rotina     VARCHAR(64) NOT NULL,
    executado  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

DELIMITER $$
CREATE TABLE IF NOT EXISTS clientes_loja (
    cliente_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email        VARCHAR(190) NOT NULL UNIQUE,
    hash_acesso  VARBINARY(128) NOT NULL COMMENT 'argon2id gerado na aplicacao',
    criado_em    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE PROCEDURE sp_cadastrar_cliente(IN p_email VARCHAR(190), IN p_hash VARBINARY(128))
BEGIN
    INSERT INTO clientes_loja (email, hash_acesso) VALUES (p_email, p_hash);
    INSERT INTO auditoria_relatorio (usuario, rotina) VALUES (p_email, 'cadastro');
END$$
DELIMITER ;
