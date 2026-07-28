using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfPasswordResetTicketStore(RyzeAuthDbContext dbContext) : IPasswordResetTicketStore
{
    public Task AddAsync(PasswordResetTicket ticket, CancellationToken cancellationToken) => dbContext.PasswordResetTickets.AddAsync(ticket, cancellationToken).AsTask();
    public Task<PasswordResetTicket?> FindByDigestAsync(string digest, CancellationToken cancellationToken) =>
        dbContext.PasswordResetTickets.SingleOrDefaultAsync(x => x.TokenDigest == digest, cancellationToken);

    public async Task InvalidateActiveForSubjectAsync(string subjectId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var active = await dbContext.PasswordResetTickets
            .Where(x => x.SubjectId == subjectId && x.UsedAt == null && x.ExpiresAt > now)
            .ToListAsync(cancellationToken);
        foreach (var ticket in active)
        {
            ticket.MarkUsed(now);
        }
    }

    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}
