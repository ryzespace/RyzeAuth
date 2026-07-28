using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfAuditTrail(RyzeAuthDbContext dbContext) : IAuditTrail
{
    public async Task RecordAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await dbContext.SecurityAuditEvents.AddAsync(auditEvent, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
