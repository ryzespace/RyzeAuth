using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IAuditTrail
{
    Task RecordAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken);
}
