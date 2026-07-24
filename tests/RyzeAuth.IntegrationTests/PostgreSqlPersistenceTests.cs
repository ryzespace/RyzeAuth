using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using RyzeAuth.Domain;
using RyzeAuth.Infrastructure.Persistence;
using Testcontainers.PostgreSql;

namespace RyzeAuth.IntegrationTests;

[CollectionDefinition("postgres", DisableParallelization = true)]
public sealed class PostgreSqlFixtureDefinition : ICollectionFixture<PostgreSqlFixture>;

[Collection("postgres")]
public sealed class PostgreSqlPersistenceTests(PostgreSqlFixture fixture)
{
    [Fact]
    public async Task MigrationsCreateSchemaAndPreserveApiKeyScopeJson()
    {
        await using var db = fixture.CreateContext();
        await db.Database.MigrateAsync();
        var now = DateTimeOffset.UtcNow;
        var organization = Organization.Create("acme-security", "Acme Security", now);
        await db.Organizations.AddAsync(organization);
        await db.ApiKeys.AddAsync(ApiKey.Create(organization.Id, "build", "rza_testprefix", "hmac-digest", ["deploy:read", "deploy:write"], "kc-user", now, now.AddDays(30)));
        await db.LoginObservations.AddAsync(LoginObservation.Create("kc-user", "ip-hash", "device-hash", "PL", 50.0647m, 19.9450m, false, false, false, "AS123", 25, false, now));
        await db.SaveChangesAsync();

        db.ChangeTracker.Clear();
        var loaded = await db.ApiKeys.SingleAsync();
        var observation = await db.LoginObservations.SingleAsync();
        loaded.Scopes.Should().BeEquivalentTo(["deploy:read", "deploy:write"]);
        loaded.IsActive(now).Should().BeTrue();
        observation.CountryCode.Should().Be("PL");
        observation.Latitude.Should().Be(50.0647m);
    }
}

public sealed class PostgreSqlFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder()
        .WithImage("postgres:17-alpine")
        .WithDatabase("ryzeauth_test")
        .WithUsername("ryzeauth")
        .WithPassword("ryzeauth-test-password")
        .Build();

    public Task InitializeAsync() => _container.StartAsync();
    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    public RyzeAuthDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<RyzeAuthDbContext>()
            .UseNpgsql(_container.GetConnectionString())
            .EnableSensitiveDataLogging(false)
            .Options;
        return new RyzeAuthDbContext(options);
    }
}

[Collection("postgres")]
public sealed class ImmutableSecurityAuditTests(PostgreSqlFixture fixture)
{
    [Fact]
    public async Task AuditRowsRejectUpdatesAndDeletes()
    {
        await using var db = fixture.CreateContext();
        await db.Database.MigrateAsync();
        await db.SecurityAuditEvents.AddAsync(SecurityAuditEvent.Create("login", "success", DateTimeOffset.UtcNow, "kc-user"));
        await db.SaveChangesAsync();

        var update = async () => await db.Database.ExecuteSqlRawAsync("UPDATE security_audit_events SET outcome = 'failure'");
        await update.Should().ThrowAsync<Exception>();
    }
}
