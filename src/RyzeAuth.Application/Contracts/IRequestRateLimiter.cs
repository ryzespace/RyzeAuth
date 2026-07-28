using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IRequestRateLimiter
{
    Task<bool> TryAcquireAsync(string category, string partition, int permitLimit, TimeSpan window, CancellationToken cancellationToken);
}
