using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IAuditReadRepository
{
    Task<IReadOnlyList<SecurityAuditEvent>> ListForSubjectAsync(string subjectId, int take, CancellationToken cancellationToken);
    Task<IReadOnlyList<SecurityAuditEvent>> ListForOrganizationAsync(Guid organizationId, int take, CancellationToken cancellationToken);
}
