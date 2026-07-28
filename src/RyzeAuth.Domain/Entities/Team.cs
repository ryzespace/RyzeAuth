namespace RyzeAuth.Domain;

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
