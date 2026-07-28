using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfOrganizationAuthorizer(IOrganizationRepository organizations) : IOrganizationAuthorizer
{
    public async Task DemandAsync(string subjectId, Guid organizationId, OrganizationAccess permission, CancellationToken cancellationToken)
    {
        var membership = await organizations.GetMembershipAsync(organizationId, subjectId, cancellationToken);
        var role = membership?.Role;
        var allowed = permission switch
        {
            OrganizationAccess.View => role is "Owner" or "OrgAdmin" or "SecurityAdmin" or "Member",
            OrganizationAccess.ManageMembers => role is "Owner" or "OrgAdmin",
            OrganizationAccess.ManageApiKeys => role is "Owner" or "OrgAdmin" or "SecurityAdmin",
            OrganizationAccess.ManageSessions => role is "Owner" or "OrgAdmin" or "SecurityAdmin",
            OrganizationAccess.ViewAudit => role is "Owner" or "OrgAdmin" or "SecurityAdmin",
            _ => false
        };

        if (!allowed)
        {
            throw new AuthorizationDeniedException("You do not have permission in this organization.");
        }
    }
}
