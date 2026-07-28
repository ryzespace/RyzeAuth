using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IOrganizationAuthorizer
{
    Task DemandAsync(string subjectId, Guid organizationId, OrganizationAccess permission, CancellationToken cancellationToken);
}
