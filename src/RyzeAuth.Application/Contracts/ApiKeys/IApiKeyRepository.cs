using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IApiKeyRepository
{
    Task AddAsync(ApiKey apiKey, CancellationToken cancellationToken);
    Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken);
    Task<ApiKey?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
