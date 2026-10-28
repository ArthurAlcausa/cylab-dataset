/* Modulo seguros (SQL Server): rotinas de backoffice de apolices */
IF SCHEMA_ID(N'seguros') IS NULL EXEC (N'CREATE SCHEMA seguros');
GO

IF OBJECT_ID(N'seguros.Apolices', N'U') IS NULL
CREATE TABLE seguros.Apolices (
    apolice_id    BIGINT IDENTITY(1,1) PRIMARY KEY,
    segurado_id    BIGINT        NOT NULL,
    Status      NVARCHAR(20)  NOT NULL DEFAULT N'ABERTO',
    premio    DECIMAL(14,2) NOT NULL DEFAULT 0,
    CriadoEm    DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

CREATE OR ALTER PROCEDURE seguros.usp_LogExecucao @Rotina SYSNAME
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LogExecucao (Rotina, Usuario, ExecutadoEm)
    VALUES (@Rotina, SUSER_SNAME(), SYSUTCDATETIME());
END;
GO

CREATE OR ALTER PROCEDURE seguros.usp_CancelarApolice
    @ApoliceId BIGINT,
    @Motivo    NVARCHAR(400)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRAN;
        UPDATE seguros.Apolices SET Status = N'CANCELADA' WHERE apolice_id = @ApoliceId;
        INSERT INTO seguros.HistoricoApolice (apolice_id, Motivo) VALUES (@ApoliceId, @Motivo);
        EXEC seguros.usp_LogExecucao N'usp_CancelarApolice';
    COMMIT;
END;
GO
