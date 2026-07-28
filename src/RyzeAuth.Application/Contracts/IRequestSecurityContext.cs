using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IRequestSecurityContext
{
    string? SubjectId { get; }
    string? CorrelationId { get; }
    string? IpAddress { get; }
}
