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

CREATE OR ALTER PROCEDURE suporte.usp_PesquisarChamados
    @Termo   NVARCHAR(200),
    @ContaId BIGINT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @sql NVARCHAR(MAX);
    EXEC suporte.usp_LogExecucao N'usp_PesquisarChamados';
    SET @sql = N'SELECT chamado_id, Status, sla_horas FROM suporte.Chamados WHERE conta_id = @c AND Titulo LIKE @t';
    EXEC sp_executesql @sql, N'@c BIGINT, @t NVARCHAR(210)', @c = @ContaId, @t = N'%' + @Termo + N'%';
END;
GO
