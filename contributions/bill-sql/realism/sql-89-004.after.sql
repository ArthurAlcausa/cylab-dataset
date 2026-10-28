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
CREATE PROCEDURE sp_relatorio_pedidos(IN p_status VARCHAR(20), IN p_usuario VARCHAR(64))
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;
    INSERT INTO auditoria_relatorio (usuario, rotina) VALUES (p_usuario, 'sp_relatorio_pedidos');
    SET @p_status = p_status;
    PREPARE stmt FROM 'SELECT pedido_id, valor_total FROM pedidos WHERE status = ? ORDER BY criado_em DESC LIMIT 500';
    EXECUTE stmt USING @p_status;
    DEALLOCATE PREPARE stmt;
END$$
DELIMITER ;
