using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfOrganizationRepository(RyzeAuthDbContext dbContext) : IOrganizationRepository
{
    public Task AddAsync(Organization organization, CancellationToken cancellationToken) => dbContext.Organizations.AddAsync(organization, cancellationToken).AsTask();
    public Task AddMembershipAsync(Membership membership, CancellationToken cancellationToken) => dbContext.Memberships.AddAsync(membership, cancellationToken).AsTask();
    public Task<Organization?> GetAsync(Guid id, CancellationToken cancellationToken) => dbContext.Organizations.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    public Task<Membership?> GetMembershipAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken) =>
        dbContext.Memberships.SingleOrDefaultAsync(x => x.OrganizationId == organizationId && x.SubjectId == subjectId && x.RevokedAt == null, cancellationToken);
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}
