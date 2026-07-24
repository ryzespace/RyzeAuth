using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Infrastructure;

#nullable disable
#pragma warning disable CA1861

namespace RyzeAuth.Infrastructure.Persistence.Migrations;

[DbContext(typeof(RyzeAuthDbContext))]
[Migration("202607240001_InitialCreate")]
public partial class InitialCreate : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "organizations",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                Slug = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                DisplayName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                DisabledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_organizations", x => x.Id));

        migrationBuilder.CreateTable(
            name: "password_reset_tickets",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                SubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                Email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                TokenDigest = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                UsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                RequestedIpHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
            },
            constraints: table => table.PrimaryKey("PK_password_reset_tickets", x => x.Id));

        migrationBuilder.CreateTable(
            name: "device_sessions",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                SubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                KeycloakSessionId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                DeviceIdHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                DisplayName = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: true),
                IpHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                UserAgent = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                CountryCode = table.Column<string>(type: "character varying(2)", maxLength: 2, nullable: true),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                IsTrusted = table.Column<bool>(type: "boolean", nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_device_sessions", x => x.Id));

        migrationBuilder.CreateTable(
            name: "security_audit_events",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                EventType = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: false),
                SubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                OrganizationId = table.Column<Guid>(type: "uuid", nullable: true),
                Outcome = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: false),
                CorrelationId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                IpHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                MetadataJson = table.Column<string>(type: "jsonb", nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_security_audit_events", x => x.Id));

        migrationBuilder.CreateTable(
            name: "teams",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                Name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_teams", x => x.Id);
                table.ForeignKey("FK_teams_organizations_OrganizationId", x => x.OrganizationId, principalTable: "organizations", principalColumn: "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "memberships",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                SubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                Role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                AttributesJson = table.Column<string>(type: "jsonb", nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_memberships", x => x.Id);
                table.ForeignKey("FK_memberships_organizations_OrganizationId", x => x.OrganizationId, principalTable: "organizations", principalColumn: "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "api_keys",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                Name = table.Column<string>(type: "character varying(120)", maxLength: 120, nullable: false),
                Prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                SecretDigest = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                Scopes = table.Column<string>(type: "jsonb", nullable: false),
                CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                CreatedBySubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_api_keys", x => x.Id);
                table.ForeignKey("FK_api_keys_organizations_OrganizationId", x => x.OrganizationId, principalTable: "organizations", principalColumn: "Id", onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex(name: "IX_organizations_Slug", table: "organizations", column: "Slug", unique: true);
        migrationBuilder.CreateIndex(name: "IX_password_reset_tickets_TokenDigest", table: "password_reset_tickets", column: "TokenDigest", unique: true);
        migrationBuilder.CreateIndex(name: "IX_password_reset_tickets_SubjectId_UsedAt_ExpiresAt", table: "password_reset_tickets", columns: new[] { "SubjectId", "UsedAt", "ExpiresAt" });
        migrationBuilder.CreateIndex(name: "IX_device_sessions_KeycloakSessionId", table: "device_sessions", column: "KeycloakSessionId", unique: true);
        migrationBuilder.CreateIndex(name: "IX_device_sessions_SubjectId_RevokedAt_LastSeenAt", table: "device_sessions", columns: new[] { "SubjectId", "RevokedAt", "LastSeenAt" });
        migrationBuilder.CreateIndex(name: "IX_security_audit_events_SubjectId_OccurredAt", table: "security_audit_events", columns: new[] { "SubjectId", "OccurredAt" });
        migrationBuilder.CreateIndex(name: "IX_security_audit_events_OrganizationId_OccurredAt", table: "security_audit_events", columns: new[] { "OrganizationId", "OccurredAt" });
        migrationBuilder.CreateIndex(name: "IX_security_audit_events_EventType_OccurredAt", table: "security_audit_events", columns: new[] { "EventType", "OccurredAt" });
        migrationBuilder.CreateIndex(name: "IX_teams_OrganizationId_Name", table: "teams", columns: new[] { "OrganizationId", "Name" }, unique: true);
        migrationBuilder.CreateIndex(name: "IX_memberships_OrganizationId_SubjectId", table: "memberships", columns: new[] { "OrganizationId", "SubjectId" }, unique: true);
        migrationBuilder.CreateIndex(name: "IX_api_keys_Prefix", table: "api_keys", column: "Prefix", unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "api_keys");
        migrationBuilder.DropTable(name: "device_sessions");
        migrationBuilder.DropTable(name: "memberships");
        migrationBuilder.DropTable(name: "password_reset_tickets");
        migrationBuilder.DropTable(name: "security_audit_events");
        migrationBuilder.DropTable(name: "teams");
        migrationBuilder.DropTable(name: "organizations");
    }
}
