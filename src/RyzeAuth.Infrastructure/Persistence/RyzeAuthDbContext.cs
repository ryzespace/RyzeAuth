using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class RyzeAuthDbContext(DbContextOptions<RyzeAuthDbContext> options) : DbContext(options)
{
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<Team> Teams => Set<Team>();
    public DbSet<Membership> Memberships => Set<Membership>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<PasswordResetTicket> PasswordResetTickets => Set<PasswordResetTicket>();
    public DbSet<DeviceSession> DeviceSessions => Set<DeviceSession>();
    public DbSet<SecurityAuditEvent> SecurityAuditEvents => Set<SecurityAuditEvent>();
    public DbSet<LoginObservation> LoginObservations => Set<LoginObservation>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        var jsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var stringListComparer = new ValueComparer<IReadOnlyList<string>>(
            (left, right) => StringListsEqual(left, right),
            list => StringListHashCode(list),
            list => SnapshotStringList(list));

        modelBuilder.Entity<Organization>(entity =>
        {
            entity.ToTable("organizations");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Slug).HasMaxLength(64).IsRequired();
            entity.HasIndex(x => x.Slug).IsUnique();
            entity.Property(x => x.DisplayName).HasMaxLength(120).IsRequired();
            entity.Property(x => x.CreatedAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.DisabledAt).HasColumnType("timestamp with time zone");
        });

        modelBuilder.Entity<Team>(entity =>
        {
            entity.ToTable("teams");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(120).IsRequired();
            entity.HasIndex(x => new { x.OrganizationId, x.Name }).IsUnique();
            entity.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Membership>(entity =>
        {
            entity.ToTable("memberships");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.SubjectId).HasMaxLength(100).IsRequired();
            entity.Property(x => x.Role).HasMaxLength(32).IsRequired();
            entity.Property(x => x.AttributesJson).HasColumnType("jsonb").IsRequired();
            entity.HasIndex(x => new { x.OrganizationId, x.SubjectId }).IsUnique();
            entity.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ApiKey>(entity =>
        {
            entity.ToTable("api_keys");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Name).HasMaxLength(120).IsRequired();
            entity.Property(x => x.Prefix).HasMaxLength(32).IsRequired();
            entity.HasIndex(x => x.Prefix).IsUnique();
            entity.Property(x => x.SecretDigest).HasMaxLength(128).IsRequired();
            entity.Property(x => x.CreatedBySubjectId).HasMaxLength(100).IsRequired();
            entity.Property(x => x.Scopes)
                .HasColumnType("jsonb")
                .HasConversion(
                    scopes => JsonSerializer.Serialize(scopes, jsonOptions),
                    json => (IReadOnlyList<string>)(JsonSerializer.Deserialize<string[]>(json, jsonOptions) ?? Array.Empty<string>()))
                .Metadata.SetValueComparer(stringListComparer);
            entity.Property(x => x.CreatedAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.ExpiresAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.RevokedAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LastUsedAt).HasColumnType("timestamp with time zone");
            entity.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PasswordResetTicket>(entity =>
        {
            entity.ToTable("password_reset_tickets");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.SubjectId).HasMaxLength(100).IsRequired();
            entity.Property(x => x.Email).HasMaxLength(320).IsRequired();
            entity.Property(x => x.TokenDigest).HasMaxLength(128).IsRequired();
            entity.HasIndex(x => x.TokenDigest).IsUnique();
            entity.Property(x => x.RequestedIpHash).HasMaxLength(128);
            entity.Property(x => x.CreatedAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.ExpiresAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.UsedAt).HasColumnType("timestamp with time zone");
            entity.HasIndex(x => new { x.SubjectId, x.UsedAt, x.ExpiresAt });
        });

        modelBuilder.Entity<DeviceSession>(entity =>
        {
            entity.ToTable("device_sessions");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.SubjectId).HasMaxLength(100).IsRequired();
            entity.Property(x => x.KeycloakSessionId).HasMaxLength(100).IsRequired();
            entity.HasIndex(x => x.KeycloakSessionId).IsUnique();
            entity.Property(x => x.DeviceIdHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.DisplayName).HasMaxLength(120);
            entity.Property(x => x.IpHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.UserAgent).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.CountryCode).HasMaxLength(2);
            entity.Property(x => x.CreatedAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.LastSeenAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.RevokedAt).HasColumnType("timestamp with time zone");
            entity.HasIndex(x => new { x.SubjectId, x.RevokedAt, x.LastSeenAt });
        });

        modelBuilder.Entity<LoginObservation>(entity =>
        {
            entity.ToTable("login_observations");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.SubjectId).HasMaxLength(100).IsRequired();
            entity.Property(x => x.IpHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.DeviceIdHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.CountryCode).HasMaxLength(2);
            entity.Property(x => x.Latitude).HasPrecision(9, 6);
            entity.Property(x => x.Longitude).HasPrecision(9, 6);
            entity.Property(x => x.Asn).HasMaxLength(32);
            entity.Property(x => x.OccurredAt).HasColumnType("timestamp with time zone");
            entity.HasIndex(x => new { x.SubjectId, x.OccurredAt });
        });

        modelBuilder.Entity<SecurityAuditEvent>(entity =>
        {
            entity.ToTable("security_audit_events");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.OccurredAt).HasColumnType("timestamp with time zone");
            entity.Property(x => x.EventType).HasMaxLength(80).IsRequired();
            entity.Property(x => x.Outcome).HasMaxLength(20).IsRequired();
            entity.Property(x => x.SubjectId).HasMaxLength(100);
            entity.Property(x => x.CorrelationId).HasMaxLength(128);
            entity.Property(x => x.IpHash).HasMaxLength(128);
            entity.Property(x => x.MetadataJson).HasColumnType("jsonb").IsRequired();
            entity.HasIndex(x => new { x.SubjectId, x.OccurredAt });
            entity.HasIndex(x => new { x.OrganizationId, x.OccurredAt });
            entity.HasIndex(x => new { x.EventType, x.OccurredAt });
        });
    }

    private static bool StringListsEqual(IReadOnlyList<string>? left, IReadOnlyList<string>? right) =>
        ReferenceEquals(left, right) || (left is not null && right is not null && left.SequenceEqual(right, StringComparer.Ordinal));

    private static int StringListHashCode(IReadOnlyList<string>? values) => values is null
        ? 0
        : values.Aggregate(0, (hash, value) => HashCode.Combine(hash, value.GetHashCode(StringComparison.Ordinal)));

    private static string[] SnapshotStringList(IReadOnlyList<string>? values) => values?.ToArray() ?? Array.Empty<string>();
}
