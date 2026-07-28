using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfDeviceSessionRepository(RyzeAuthDbContext dbContext) : IDeviceSessionRepository
{
    public Task<DeviceSession?> GetAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.DeviceSessions.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

    public Task<DeviceSession?> FindByKeycloakSessionIdAsync(string keycloakSessionId, CancellationToken cancellationToken) =>
        dbContext.DeviceSessions.SingleOrDefaultAsync(x => x.KeycloakSessionId == keycloakSessionId, cancellationToken);

    public async Task<IReadOnlyList<DeviceSession>> ListActiveForSubjectAsync(string subjectId, CancellationToken cancellationToken) =>
        await dbContext.DeviceSessions
            .Where(x => x.SubjectId == subjectId && x.RevokedAt == null)
            .OrderByDescending(x => x.LastSeenAt)
            .ToListAsync(cancellationToken);

    public Task AddAsync(DeviceSession session, CancellationToken cancellationToken) => dbContext.DeviceSessions.AddAsync(session, cancellationToken).AsTask();
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}
