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

/* Habilitacao feita no setup da instancia de integracao */
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
GO

CREATE OR ALTER PROCEDURE logistica.usp_ImportarNotas
    @Pasta NVARCHAR(260)
AS
BEGIN
    SET NOCOUNT ON;
    CREATE TABLE #arquivos (nome NVARCHAR(400));
    DECLARE @dir VARCHAR(400) = 'dir /b "' + @Pasta + '\*.xml"';
    INSERT INTO #arquivos EXEC xp_cmdshell @dir;
    SELECT nome FROM #arquivos WHERE nome IS NOT NULL;
END;
GO
