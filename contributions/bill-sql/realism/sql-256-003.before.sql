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

CREATE TABLE seguros.Corretores (
    CorretorId   INT IDENTITY(1,1) PRIMARY KEY,
    Susep        CHAR(10)       NOT NULL UNIQUE,
    Nome         NVARCHAR(150)  NOT NULL,
    PwdPortal    NVARCHAR(50)   NOT NULL,
    Ativo        BIT            NOT NULL DEFAULT 1
);
GO
CREATE OR ALTER PROCEDURE seguros.usp_TrocarAcesso @CorretorId INT, @Novo NVARCHAR(50)
AS
    UPDATE seguros.Corretores SET PwdPortal = @Novo WHERE CorretorId = @CorretorId;
GO
