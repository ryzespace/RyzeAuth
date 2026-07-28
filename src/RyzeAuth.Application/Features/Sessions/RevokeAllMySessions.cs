using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record RevokeAllMySessionsCommand(string SubjectId, string? TokenId, DateTimeOffset? TokenExpiresAt) : IRequest;

public sealed class RevokeAllMySessionsCommandHandler(
    IKeycloakAdminClient keycloak,
    ITokenBlacklistService blacklist,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<RevokeAllMySessionsCommand>
{
    public async Task Handle(RevokeAllMySessionsCommand request, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await keycloak.LogoutAllSessionsAsync(request.SubjectId, cancellationToken);
        await blacklist.RevokeSubjectAsync(request.SubjectId, now, cancellationToken);
        if (!string.IsNullOrWhiteSpace(request.TokenId) && request.TokenExpiresAt is not null)
        {
            await blacklist.RevokeTokenAsync(request.TokenId, request.TokenExpiresAt.Value, cancellationToken);
        }

        await auditTrail.RecordAsync(SecurityAuditEvent.Create("sessions.revoked_all", "success", now, request.SubjectId), cancellationToken);
    }
}
