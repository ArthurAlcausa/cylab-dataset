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

CREATE OR ALTER PROCEDURE logistica.usp_ExpurgarMovimentos
    @Tabela  SYSNAME,
    @DiasRet INT = 365
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @cmd NVARCHAR(MAX);
    IF @DiasRet < 90 THROW 50010, N'Retencao minima de 90 dias', 1;
    IF OBJECT_ID(N'logistica.' + @Tabela, N'U') IS NULL THROW 50011, N'Tabela inexistente', 1;
    SET @cmd = N'DELETE FROM logistica.' + QUOTENAME(@Tabela) + N' WHERE CriadoEm < DATEADD(DAY, -@d, SYSUTCDATETIME())';
    EXEC sp_executesql @cmd, N'@d INT', @d = @DiasRet;
    EXEC logistica.usp_LogExecucao N'usp_ExpurgarMovimentos';
END;
GO
