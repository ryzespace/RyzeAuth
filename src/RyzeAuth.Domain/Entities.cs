namespace RyzeAuth.Domain;

public sealed class Organization
{
    private Organization() { }

    public Guid Id { get; private set; }
    public string Slug { get; private set; } = null!;
    public string DisplayName { get; private set; } = null!;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? DisabledAt { get; private set; }

    public static Organization Create(string slug, string displayName, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slug);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        return new Organization
        {
            Id = Guid.NewGuid(),
            Slug = slug.Trim().ToLowerInvariant(),
            DisplayName = displayName.Trim(),
            CreatedAt = now
        };
    }
}

public sealed class Team
{
    private Team() { }

    public Guid Id { get; private set; }
    public Guid OrganizationId { get; private set; }
    public string Name { get; private set; } = null!;
    public DateTimeOffset CreatedAt { get; private set; }

    public static Team Create(Guid organizationId, string name, DateTimeOffset now) => new()
    {
        Id = Guid.NewGuid(),
        OrganizationId = organizationId,
        Name = name.Trim(),
        CreatedAt = now
    };
}

public sealed class Membership
{
    private Membership() { }

    public Guid Id { get; private set; }
    public Guid OrganizationId { get; private set; }
    public string SubjectId { get; private set; } = null!;
    public string Role { get; private set; } = null!;
    public string AttributesJson { get; private set; } = "{}";
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }

    public static Membership Create(
        Guid organizationId,
        string subjectId,
        string role,
        string attributesJson,
        DateTimeOffset now) => new()
        {
            Id = Guid.NewGuid(),
            OrganizationId = organizationId,
            SubjectId = subjectId,
            Role = role,
            AttributesJson = attributesJson,
            CreatedAt = now
        };
}

public sealed class ApiKey
{
    private ApiKey() { }

    public Guid Id { get; private set; }
    public Guid OrganizationId { get; private set; }
    public string Name { get; private set; } = null!;
    public string Prefix { get; private set; } = null!;
    public string SecretDigest { get; private set; } = null!;
    public IReadOnlyList<string> Scopes { get; private set; } = [];
    public DateTimeOffset CreatedAt { get; private set; }
    public string CreatedBySubjectId { get; private set; } = null!;
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public DateTimeOffset? LastUsedAt { get; private set; }

    public static ApiKey Create(
        Guid organizationId,
        string name,
        string prefix,
        string secretDigest,
        IReadOnlyList<string> scopes,
        string createdBySubjectId,
        DateTimeOffset now,
        DateTimeOffset? expiresAt) => new()
        {
            Id = Guid.NewGuid(),
            OrganizationId = organizationId,
            Name = name.Trim(),
            Prefix = prefix,
            SecretDigest = secretDigest,
            Scopes = scopes.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            CreatedBySubjectId = createdBySubjectId,
            CreatedAt = now,
            ExpiresAt = expiresAt
        };

    public bool IsActive(DateTimeOffset now) => RevokedAt is null && (ExpiresAt is null || ExpiresAt > now);
    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
    public void MarkUsed(DateTimeOffset now) => LastUsedAt = now;
}

public sealed class PasswordResetTicket
{
    private PasswordResetTicket() { }

    public Guid Id { get; private set; }
    public string SubjectId { get; private set; } = null!;
    public string Email { get; private set; } = null!;
    public string TokenDigest { get; private set; } = null!;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? UsedAt { get; private set; }
    public string? RequestedIpHash { get; private set; }

    public static PasswordResetTicket Issue(
        string subjectId,
        string email,
        string tokenDigest,
        DateTimeOffset now,
        DateTimeOffset expiresAt,
        string? requestedIpHash) => new()
        {
            Id = Guid.NewGuid(),
            SubjectId = subjectId,
            Email = email,
            TokenDigest = tokenDigest,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            RequestedIpHash = requestedIpHash
        };

    public bool IsUsable(DateTimeOffset now) => UsedAt is null && ExpiresAt > now;
    public void MarkUsed(DateTimeOffset now) => UsedAt ??= now;
}

public sealed class DeviceSession
{
    private DeviceSession() { }

    public Guid Id { get; private set; }
    public string SubjectId { get; private set; } = null!;
    public string KeycloakSessionId { get; private set; } = null!;
    public string DeviceIdHash { get; private set; } = null!;
    public string? DisplayName { get; private set; }
    public string IpHash { get; private set; } = null!;
    public string UserAgent { get; private set; } = null!;
    public string? CountryCode { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset LastSeenAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public bool IsTrusted { get; private set; }

    public static DeviceSession Create(
        string subjectId,
        string keycloakSessionId,
        string deviceIdHash,
        string ipHash,
        string userAgent,
        string? countryCode,
        DateTimeOffset now) => new()
        {
            Id = Guid.NewGuid(),
            SubjectId = subjectId,
            KeycloakSessionId = keycloakSessionId,
            DeviceIdHash = deviceIdHash,
            IpHash = ipHash,
            UserAgent = userAgent,
            CountryCode = countryCode,
            CreatedAt = now,
            LastSeenAt = now
        };

    public void Rename(string displayName) => DisplayName = displayName.Trim();
    public void SetTrusted(bool trusted) => IsTrusted = trusted;
    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
    public void Touch(DateTimeOffset now) => LastSeenAt = now;
}

public sealed class SecurityAuditEvent
{
    private SecurityAuditEvent() { }

    public Guid Id { get; private set; }
    public DateTimeOffset OccurredAt { get; private set; }
    public string EventType { get; private set; } = null!;
    public string? SubjectId { get; private set; }
    public Guid? OrganizationId { get; private set; }
    public string Outcome { get; private set; } = null!;
    public string? CorrelationId { get; private set; }
    public string? IpHash { get; private set; }
    public string MetadataJson { get; private set; } = "{}";

    public static SecurityAuditEvent Create(
        string eventType,
        string outcome,
        DateTimeOffset occurredAt,
        string? subjectId = null,
        Guid? organizationId = null,
        string? correlationId = null,
        string? ipHash = null,
        string metadataJson = "{}") => new()
        {
            Id = Guid.NewGuid(),
            EventType = eventType,
            Outcome = outcome,
            OccurredAt = occurredAt,
            SubjectId = subjectId,
            OrganizationId = organizationId,
            CorrelationId = correlationId,
            IpHash = ipHash,
            MetadataJson = metadataJson
        };
}

public sealed class LoginObservation
{
    private LoginObservation() { }

    public Guid Id { get; private set; }
    public string SubjectId { get; private set; } = null!;
    public string IpHash { get; private set; } = null!;
    public string DeviceIdHash { get; private set; } = null!;
    public string? CountryCode { get; private set; }
    public decimal? Latitude { get; private set; }
    public decimal? Longitude { get; private set; }
    public bool IsVpn { get; private set; }
    public bool IsProxy { get; private set; }
    public bool IsTor { get; private set; }
    public string? Asn { get; private set; }
    public int RiskScore { get; private set; }
    public bool StepUpRequired { get; private set; }
    public DateTimeOffset OccurredAt { get; private set; }

    public static LoginObservation Create(
        string subjectId,
        string ipHash,
        string deviceIdHash,
        string? countryCode,
        decimal? latitude,
        decimal? longitude,
        bool isVpn,
        bool isProxy,
        bool isTor,
        string? asn,
        int riskScore,
        bool stepUpRequired,
        DateTimeOffset occurredAt) => new()
        {
            Id = Guid.NewGuid(),
            SubjectId = subjectId,
            IpHash = ipHash,
            DeviceIdHash = deviceIdHash,
            CountryCode = countryCode,
            Latitude = latitude,
            Longitude = longitude,
            IsVpn = isVpn,
            IsProxy = isProxy,
            IsTor = isTor,
            Asn = asn,
            RiskScore = riskScore,
            StepUpRequired = stepUpRequired,
            OccurredAt = occurredAt
        };
}
