using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IPasswordResetTicketStore
{
    Task AddAsync(PasswordResetTicket ticket, CancellationToken cancellationToken);
    Task<PasswordResetTicket?> FindByDigestAsync(string digest, CancellationToken cancellationToken);
    Task InvalidateActiveForSubjectAsync(string subjectId, DateTimeOffset now, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
