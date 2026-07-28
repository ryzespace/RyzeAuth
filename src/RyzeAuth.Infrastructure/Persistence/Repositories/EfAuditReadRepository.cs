using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfAuditReadRepository(RyzeAuthDbContext dbContext) : IAuditReadRepository
{
    public async Task<IReadOnlyList<SecurityAuditEvent>> ListForSubjectAsync(string subjectId, int take, CancellationToken cancellationToken) =>
        await dbContext.SecurityAuditEvents
            .Where(x => x.SubjectId == subjectId)
            .OrderByDescending(x => x.OccurredAt)
            .Take(take)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<SecurityAuditEvent>> ListForOrganizationAsync(Guid organizationId, int take, CancellationToken cancellationToken) =>
        await dbContext.SecurityAuditEvents
            .Where(x => x.OrganizationId == organizationId)
            .OrderByDescending(x => x.OccurredAt)
            .Take(take)
            .ToListAsync(cancellationToken);
}
