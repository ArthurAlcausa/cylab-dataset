/* Modulo logistica (SQL Server): rotinas de backoffice de estoque_mov */
IF SCHEMA_ID(N'logistica') IS NULL EXEC (N'CREATE SCHEMA logistica');
GO

IF OBJECT_ID(N'logistica.EstoqueMov', N'U') IS NULL
CREATE TABLE logistica.EstoqueMov (
    mov_id    BIGINT IDENTITY(1,1) PRIMARY KEY,
    filial_id    BIGINT        NOT NULL,
    Status      NVARCHAR(20)  NOT NULL DEFAULT N'ABERTO',
    quantidade    DECIMAL(14,2) NOT NULL DEFAULT 0,
    CriadoEm    DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

CREATE OR ALTER PROCEDURE logistica.usp_LogExecucao @Rotina SYSNAME
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LogExecucao (Rotina, Usuario, ExecutadoEm)
    VALUES (@Rotina, SUSER_SNAME(), SYSUTCDATETIME());
END;
GO

/* xp_cmdshell permanece desabilitado na instancia de integracao */
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
GO

CREATE OR ALTER PROCEDURE logistica.usp_ImportarNotas
    @LoteId BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    /* A listagem dos XML e feita pelo servico de ingestao, que grava em logistica.ArquivosRecebidos. */
    SELECT NomeArquivo
      FROM logistica.ArquivosRecebidos
     WHERE LoteId = @LoteId AND Processado = 0;
END;
GO
