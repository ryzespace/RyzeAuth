using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RyzeAuth.Infrastructure.Persistence.Migrations;

[DbContext(typeof(RyzeAuthDbContext))]
[Migration("202607240003_ImmutableSecurityAudit")]
public partial class ImmutableSecurityAudit : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("""
            CREATE OR REPLACE FUNCTION prevent_security_audit_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'security_audit_events is append-only';
            END;
            $$;
            """);
        migrationBuilder.Sql("""
            CREATE TRIGGER security_audit_events_append_only
            BEFORE UPDATE OR DELETE ON security_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION prevent_security_audit_mutation();
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql("DROP TRIGGER IF EXISTS security_audit_events_append_only ON security_audit_events;");
        migrationBuilder.Sql("DROP FUNCTION IF EXISTS prevent_security_audit_mutation();");
    }
}
