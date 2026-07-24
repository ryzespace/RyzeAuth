using Microsoft.EntityFrameworkCore;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Persistence;

public sealed class EfApiKeyRepository(RyzeAuthDbContext dbContext) : IApiKeyRepository
{
    public Task AddAsync(ApiKey apiKey, CancellationToken cancellationToken) => dbContext.ApiKeys.AddAsync(apiKey, cancellationToken).AsTask();
    public Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken) =>
        dbContext.ApiKeys.SingleOrDefaultAsync(x => x.Prefix == prefix, cancellationToken);
    public Task<ApiKey?> GetAsync(Guid id, CancellationToken cancellationToken) => dbContext.ApiKeys.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}

public sealed class EfOrganizationRepository(RyzeAuthDbContext dbContext) : IOrganizationRepository
{
    public Task AddAsync(Organization organization, CancellationToken cancellationToken) => dbContext.Organizations.AddAsync(organization, cancellationToken).AsTask();
    public Task AddMembershipAsync(Membership membership, CancellationToken cancellationToken) => dbContext.Memberships.AddAsync(membership, cancellationToken).AsTask();
    public Task<Organization?> GetAsync(Guid id, CancellationToken cancellationToken) => dbContext.Organizations.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
    public Task<Membership?> GetMembershipAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken) =>
        dbContext.Memberships.SingleOrDefaultAsync(x => x.OrganizationId == organizationId && x.SubjectId == subjectId && x.RevokedAt == null, cancellationToken);
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}

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

public sealed class EfAuditTrail(RyzeAuthDbContext dbContext) : IAuditTrail
{
    public async Task RecordAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        await dbContext.SecurityAuditEvents.AddAsync(auditEvent, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}

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

public sealed class EfDeviceSessionRepository(RyzeAuthDbContext dbContext) : IDeviceSessionRepository
{
    public Task<DeviceSession?> GetAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.DeviceSessions.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

    public Task<DeviceSession?> FindByKeycloakSessionIdAsync(string keycloakSessionId, CancellationToken cancellationToken) =>
        dbContext.DeviceSessions.SingleOrDefaultAsync(x => x.KeycloakSessionId == keycloakSessionId, cancellationToken);

    public async Task<IReadOnlyList<DeviceSession>> ListActiveForSubjectAsync(string subjectId, CancellationToken cancellationToken) =>
        await dbContext.DeviceSessions
            .Where(x => x.SubjectId == subjectId && x.RevokedAt == null)
            .OrderByDescending(x => x.LastSeenAt)
            .ToListAsync(cancellationToken);

    public Task AddAsync(DeviceSession session, CancellationToken cancellationToken) => dbContext.DeviceSessions.AddAsync(session, cancellationToken).AsTask();
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}

public sealed class EfLoginObservationRepository(RyzeAuthDbContext dbContext) : ILoginObservationRepository
{
    public Task<LoginObservation?> GetLatestForSubjectAsync(string subjectId, CancellationToken cancellationToken) =>
        dbContext.LoginObservations
            .Where(x => x.SubjectId == subjectId)
            .OrderByDescending(x => x.OccurredAt)
            .FirstOrDefaultAsync(cancellationToken);

    public Task AddAsync(LoginObservation observation, CancellationToken cancellationToken) => dbContext.LoginObservations.AddAsync(observation, cancellationToken).AsTask();
    public Task SaveChangesAsync(CancellationToken cancellationToken) => dbContext.SaveChangesAsync(cancellationToken);
}

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
