using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IAdaptiveRiskService
{
    Task<AdaptiveRiskDecision> AssessAsync(LoginRiskInput input, CancellationToken cancellationToken);
    Task RecordSuccessfulLoginAsync(LoginRiskInput input, AdaptiveRiskDecision decision, CancellationToken cancellationToken);
}
