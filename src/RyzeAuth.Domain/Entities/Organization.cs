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
