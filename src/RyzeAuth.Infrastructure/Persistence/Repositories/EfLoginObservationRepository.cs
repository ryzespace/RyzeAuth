using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfLoginObservationRepository(RyzeAuthDbContext dbContext) : ILoginObservationRepository
{
    public Task<LoginObservation?> GetLatestForSubjectAsync(string subjectId, CancellationToken cancellationToken) =>
        dbContext.LoginObservations
            .Where(x => x.SubjectId == subjectId)
            .OrderByDescending(x => x.OccurredAt)
            .FirstOrDefaultAsync(cancellationToken);

    public Task AddAsync(LoginObservation observation, CancellationToken cancellationToken) => dbContext.LoginObservations.AddAsync(observation, cancellationToken).AsTask();
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}
