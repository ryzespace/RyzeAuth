using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IOrganizationRepository
{
    Task AddAsync(Organization organization, CancellationToken cancellationToken);
    Task AddMembershipAsync(Membership membership, CancellationToken cancellationToken);
    Task<Organization?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<Membership?> GetMembershipAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}
