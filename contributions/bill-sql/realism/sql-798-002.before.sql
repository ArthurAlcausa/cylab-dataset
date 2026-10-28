/* Modulo suporte (SQL Server): rotinas de backoffice de chamados */
IF SCHEMA_ID(N'suporte') IS NULL EXEC (N'CREATE SCHEMA suporte');
GO

IF OBJECT_ID(N'suporte.Chamados', N'U') IS NULL
CREATE TABLE suporte.Chamados (
    chamado_id    BIGINT IDENTITY(1,1) PRIMARY KEY,
    conta_id    BIGINT        NOT NULL,
    Status      NVARCHAR(20)  NOT NULL DEFAULT N'ABERTO',
    sla_horas    DECIMAL(14,2) NOT NULL DEFAULT 0,
    CriadoEm    DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

CREATE OR ALTER PROCEDURE suporte.usp_LogExecucao @Rotina SYSNAME
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LogExecucao (Rotina, Usuario, ExecutadoEm)
    VALUES (@Rotina, SUSER_SNAME(), SYSUTCDATETIME());
END;
GO

USE master;
GO
IF SUSER_ID(N'svc_suporte') IS NULL
    CREATE LOGIN svc_suporte WITH PASSWORD = 'Sup0rte#Prod', CHECK_POLICY = OFF, DEFAULT_DATABASE = ERP;
GO
USE ERP;
GO
IF USER_ID(N'svc_suporte') IS NULL
    CREATE USER svc_suporte FOR LOGIN svc_suporte WITH DEFAULT_SCHEMA = suporte;
GRANT SELECT, UPDATE ON SCHEMA::suporte TO svc_suporte;
GO
