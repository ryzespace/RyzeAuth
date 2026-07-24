using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable
#pragma warning disable CA1861

namespace RyzeAuth.Infrastructure.Persistence.Migrations;

[DbContext(typeof(RyzeAuthDbContext))]
[Migration("202607240002_LoginObservations")]
public partial class LoginObservations : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "login_observations",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                SubjectId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                IpHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                DeviceIdHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                CountryCode = table.Column<string>(type: "character varying(2)", maxLength: 2, nullable: true),
                Latitude = table.Column<decimal>(type: "numeric(9,6)", precision: 9, scale: 6, nullable: true),
                Longitude = table.Column<decimal>(type: "numeric(9,6)", precision: 9, scale: 6, nullable: true),
                IsVpn = table.Column<bool>(type: "boolean", nullable: false),
                IsProxy = table.Column<bool>(type: "boolean", nullable: false),
                IsTor = table.Column<bool>(type: "boolean", nullable: false),
                Asn = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                RiskScore = table.Column<int>(type: "integer", nullable: false),
                StepUpRequired = table.Column<bool>(type: "boolean", nullable: false),
                OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table => table.PrimaryKey("PK_login_observations", x => x.Id));

        migrationBuilder.CreateIndex(
            name: "IX_login_observations_SubjectId_OccurredAt",
            table: "login_observations",
            columns: new[] { "SubjectId", "OccurredAt" });
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "login_observations");
    }
}
