/* Modulo financeiro (SQL Server): rotinas de backoffice de faturas */
IF SCHEMA_ID(N'financeiro') IS NULL EXEC (N'CREATE SCHEMA financeiro');
GO

IF OBJECT_ID(N'financeiro.Faturas', N'U') IS NULL
CREATE TABLE financeiro.Faturas (
    fatura_id    BIGINT IDENTITY(1,1) PRIMARY KEY,
    empresa_id    BIGINT        NOT NULL,
    Status      NVARCHAR(20)  NOT NULL DEFAULT N'ABERTO',
    valor_liquido    DECIMAL(14,2) NOT NULL DEFAULT 0,
    CriadoEm    DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

CREATE OR ALTER PROCEDURE financeiro.usp_LogExecucao @Rotina SYSNAME
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LogExecucao (Rotina, Usuario, ExecutadoEm)
    VALUES (@Rotina, SUSER_SNAME(), SYSUTCDATETIME());
END;
GO

CREATE OR ALTER PROCEDURE financeiro.usp_ExportarRemessa
    @Arquivo NVARCHAR(260)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @cmd VARCHAR(8000);
    EXEC financeiro.usp_LogExecucao N'usp_ExportarRemessa';
    SET @cmd = 'bcp "SELECT fatura_id, valor_liquido FROM ERP.financeiro.Faturas WHERE Status = ''ABERTO''" queryout "'
             + @Arquivo + '" -c -t; -T -S localhost';
    EXEC master..xp_cmdshell @cmd, NO_OUTPUT;
END;
GO
