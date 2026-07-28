using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record RevokeApiKeyCommand(Guid OrganizationId, Guid ApiKeyId, string ActorSubjectId) : IRequest;

public sealed class RevokeApiKeyCommandHandler(
    IApiKeyRepository apiKeys,
    IOrganizationAuthorizer authorizer,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<RevokeApiKeyCommand>
{
    public async Task Handle(RevokeApiKeyCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageApiKeys, cancellationToken);
        var key = await apiKeys.GetAsync(request.ApiKeyId, cancellationToken);
        if (key is null || key.OrganizationId != request.OrganizationId)
        {
            throw new NotFoundException("API key does not exist.");
        }

        key.Revoke(clock.UtcNow);
        await apiKeys.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("api_key.revoked", "success", clock.UtcNow,
            request.ActorSubjectId, request.OrganizationId, metadataJson: "{\"keyId\":\"" + key.Id + "\"}"), cancellationToken);
    }
}
