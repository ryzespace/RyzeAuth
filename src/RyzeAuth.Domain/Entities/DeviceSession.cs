namespace RyzeAuth.Domain;

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
