namespace RyzeAuth.Domain;

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
