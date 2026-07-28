using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record CreateApiKeyCommand(
    Guid OrganizationId,
    string ActorSubjectId,
    string Name,
    IReadOnlyList<string> Scopes,
    DateTimeOffset? ExpiresAt) : IRequest<CreateApiKeyResult>;

public sealed record CreateApiKeyResult(Guid Id, string ApiKey, string Prefix, DateTimeOffset? ExpiresAt);

public sealed class CreateApiKeyCommandValidator : AbstractValidator<CreateApiKeyCommand>
{
    public CreateApiKeyCommandValidator()
    {
        RuleFor(x => x.OrganizationId).NotEmpty();
        RuleFor(x => x.ActorSubjectId).NotEmpty();
        RuleFor(x => x.Name).NotEmpty().MaximumLength(120);
        RuleFor(x => x.Scopes).NotEmpty().Must(scopes => scopes.All(scope =>
            System.Text.RegularExpressions.Regex.IsMatch(scope, "^[a-z][a-z0-9:_-]{1,80}$")))
            .WithMessage("Each scope must be a lowercase scope identifier.");
        RuleFor(x => x.ExpiresAt).Must(x => x is null || x > DateTimeOffset.UtcNow)
            .WithMessage("Expiration must be in the future.");
    }
}

public sealed class CreateApiKeyCommandHandler(
    IApiKeyRepository apiKeys,
    IOrganizationAuthorizer authorizer,
    IOpaqueTokenService tokens,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<CreateApiKeyCommand, CreateApiKeyResult>
{
    public async Task<CreateApiKeyResult> Handle(CreateApiKeyCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageApiKeys, cancellationToken);
        var now = clock.UtcNow;
        var entropy = tokens.CreateToken();
        var prefix = $"rza_{entropy[..12]}";
        var apiKey = $"{prefix}.{entropy}";
        var entity = ApiKey.Create(request.OrganizationId, request.Name, prefix, tokens.Digest(apiKey), request.Scopes,
            request.ActorSubjectId, now, request.ExpiresAt);

        await apiKeys.AddAsync(entity, cancellationToken);
        await apiKeys.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("api_key.created", "success", now,
            request.ActorSubjectId, request.OrganizationId, metadataJson: "{\"keyId\":\"" + entity.Id + "\"}"), cancellationToken);
        return new CreateApiKeyResult(entity.Id, apiKey, prefix, entity.ExpiresAt);
    }
}
