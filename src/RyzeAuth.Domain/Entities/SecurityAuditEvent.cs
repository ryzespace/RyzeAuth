namespace RyzeAuth.Domain;

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
