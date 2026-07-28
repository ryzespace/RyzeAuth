using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IDeviceSessionRepository
{
    Task<DeviceSession?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<DeviceSession?> FindByKeycloakSessionIdAsync(string keycloakSessionId, CancellationToken cancellationToken);
    Task<IReadOnlyList<DeviceSession>> ListActiveForSubjectAsync(string subjectId, CancellationToken cancellationToken);
    Task AddAsync(DeviceSession session, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
