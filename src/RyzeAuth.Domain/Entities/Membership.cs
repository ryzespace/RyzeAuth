namespace RyzeAuth.Domain;

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
