using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record RiskContext(string SubjectOrEmail, string? IpAddress, string? UserAgent, string? CountryCode);
