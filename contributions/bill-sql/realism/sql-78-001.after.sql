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
    @LoteId BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    EXEC financeiro.usp_LogExecucao N'usp_ExportarRemessa';
    /* A exportacao de arquivo e feita pelo job SSIS 'RemessaBancaria', que le a fila abaixo. */
    INSERT INTO financeiro.FilaExportacao (LoteId, SolicitadoPor, SolicitadoEm)
    VALUES (@LoteId, SUSER_SNAME(), SYSUTCDATETIME());
END;
GO
