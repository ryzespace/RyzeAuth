using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record LoginRiskInput(string SubjectId, string? IpAddress, string? UserAgent, string? DeviceId, DateTimeOffset OccurredAt);
