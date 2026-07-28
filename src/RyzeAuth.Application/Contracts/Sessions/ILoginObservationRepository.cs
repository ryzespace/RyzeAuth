using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface ILoginObservationRepository
{
    Task<LoginObservation?> GetLatestForSubjectAsync(string subjectId, CancellationToken cancellationToken);
    Task AddAsync(LoginObservation observation, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
