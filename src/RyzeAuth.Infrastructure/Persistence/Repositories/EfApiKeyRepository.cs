using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfApiKeyRepository(RyzeAuthDbContext dbContext) : IApiKeyRepository
{
    public Task AddAsync(ApiKey apiKey, CancellationToken cancellationToken) => dbContext.ApiKeys.AddAsync(apiKey, cancellationToken).AsTask();
    public Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken) =>
        dbContext.ApiKeys.SingleOrDefaultAsync(x => x.Prefix == prefix, cancellationToken);
    public Task<ApiKey?> GetAsync(Guid id, CancellationToken cancellationToken) => dbContext.ApiKeys.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}
