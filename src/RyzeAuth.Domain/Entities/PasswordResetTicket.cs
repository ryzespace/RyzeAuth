namespace RyzeAuth.Domain;

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
