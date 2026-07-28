using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record SecurityAuditResult(
    Guid Id,
    DateTimeOffset OccurredAt,
    string EventType,
    string Outcome,
    Guid? OrganizationId,
    string MetadataJson);

public sealed record GetMySecurityAuditQuery(string SubjectId, int Take) : IRequest<IReadOnlyList<SecurityAuditResult>>;

public sealed class GetMySecurityAuditQueryHandler(IAuditReadRepository audit) : IRequestHandler<GetMySecurityAuditQuery, IReadOnlyList<SecurityAuditResult>>
{
    public async Task<IReadOnlyList<SecurityAuditResult>> Handle(GetMySecurityAuditQuery request, CancellationToken cancellationToken)
    {
        var events = await audit.ListForSubjectAsync(request.SubjectId, Math.Clamp(request.Take, 1, 100), cancellationToken);
        return events.Select(MapAudit).ToArray();
    }

    internal static SecurityAuditResult MapAudit(SecurityAuditEvent item) => new(item.Id, item.OccurredAt, item.EventType, item.Outcome, item.OrganizationId, item.MetadataJson);
}

public sealed record GetOrganizationSecurityAuditQuery(Guid OrganizationId, string ActorSubjectId, int Take) : IRequest<IReadOnlyList<SecurityAuditResult>>;

public sealed class GetOrganizationSecurityAuditQueryHandler(
    IAuditReadRepository audit,
    IOrganizationAuthorizer authorizer) : IRequestHandler<GetOrganizationSecurityAuditQuery, IReadOnlyList<SecurityAuditResult>>
{
    public async Task<IReadOnlyList<SecurityAuditResult>> Handle(GetOrganizationSecurityAuditQuery request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ViewAudit, cancellationToken);
        var events = await audit.ListForOrganizationAsync(request.OrganizationId, Math.Clamp(request.Take, 1, 100), cancellationToken);
        return events.Select(GetMySecurityAuditQueryHandler.MapAudit).ToArray();
    }
}
