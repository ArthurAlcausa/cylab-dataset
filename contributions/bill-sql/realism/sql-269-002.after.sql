-- Modulo financeiro (MySQL 8): procedures de relatorio de faturas
CREATE TABLE IF NOT EXISTS faturas (
    fatura_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    empresa_id   BIGINT UNSIGNED NOT NULL,
    status     VARCHAR(20) NOT NULL DEFAULT 'ABERTO',
    valor_liquido   DECIMAL(14,2) NOT NULL DEFAULT 0,
    criado_em  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (fatura_id),
    KEY ix_empresa_id (empresa_id, criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auditoria_relatorio (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    usuario    VARCHAR(64) NOT NULL,
    rotina     VARCHAR(64) NOT NULL,
    executado  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

DELIMITER $$
CREATE PROCEDURE sp_saldo_empresa(IN p_empresa BIGINT)
BEGIN
    SELECT empresa_id, SUM(valor_liquido) AS saldo
      FROM faturas
     WHERE empresa_id = p_empresa AND status = 'ABERTO'
     GROUP BY empresa_id;
END$$
DELIMITER ;

CREATE USER IF NOT EXISTS 'fin_app'@'10.20.%' IDENTIFIED WITH caching_sha2_password;
GRANT SELECT, INSERT, UPDATE ON financeiro.faturas TO 'fin_app'@'10.20.%';
GRANT EXECUTE ON PROCEDURE financeiro.sp_saldo_empresa TO 'fin_app'@'10.20.%';
