using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record TokenIntrospectionResult(bool Active, string? SubjectId, string? ClientId, IReadOnlyList<string> Scopes, DateTimeOffset? ExpiresAt);
