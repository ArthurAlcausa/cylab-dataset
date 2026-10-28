-- Modulo logistica (MySQL 8): procedures de relatorio de estoque_mov
CREATE TABLE IF NOT EXISTS estoque_mov (
    mov_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    filial_id   BIGINT UNSIGNED NOT NULL,
    status     VARCHAR(20) NOT NULL DEFAULT 'ABERTO',
    quantidade   DECIMAL(14,2) NOT NULL DEFAULT 0,
    criado_em  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mov_id),
    KEY ix_filial_id (filial_id, criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auditoria_relatorio (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    usuario    VARCHAR(64) NOT NULL,
    rotina     VARCHAR(64) NOT NULL,
    executado  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

DELIMITER $$
CREATE PROCEDURE sp_ajustar_estoque(IN p_filial BIGINT, IN p_motivo VARCHAR(200), IN p_usuario VARCHAR(64))
BEGIN
    DECLARE v_linhas INT DEFAULT 0;
    START TRANSACTION;
    SET @upd = CONCAT('UPDATE estoque_mov SET status = ''AJUSTADO'', obs = ''', p_motivo, ''' WHERE filial_id = ', p_filial);
    PREPARE s1 FROM @upd;
    EXECUTE s1;
    SET v_linhas = ROW_COUNT();
    DEALLOCATE PREPARE s1;
    INSERT INTO auditoria_relatorio (usuario, rotina) VALUES (p_usuario, CONCAT('ajuste:', v_linhas));
    COMMIT;
END$$
DELIMITER ;
