using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IRiskEngine
{
    Task<RiskAssessment> AssessAsync(RiskContext context, CancellationToken cancellationToken);
    Task RegisterFailureAsync(string kind, string principal, string? ipAddress, CancellationToken cancellationToken);
}
