using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record IntrospectApiKeyQuery(string ApiKey, string? RequiredScope) : IRequest<ApiKeyIntrospectionResult>;
public sealed record ApiKeyIntrospectionResult(bool Active, Guid? OrganizationId, IReadOnlyList<string> Scopes, Guid? KeyId, string? Reason);

public sealed class IntrospectApiKeyQueryHandler(
    IApiKeyRepository apiKeys,
    IOpaqueTokenService tokens,
    IClock clock) : IRequestHandler<IntrospectApiKeyQuery, ApiKeyIntrospectionResult>
{
    public async Task<ApiKeyIntrospectionResult> Handle(IntrospectApiKeyQuery request, CancellationToken cancellationToken)
    {
        var separator = request.ApiKey.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return new(false, null, [], null, "malformed");
        }

        var prefix = request.ApiKey[..separator];
        var key = await apiKeys.FindByPrefixAsync(prefix, cancellationToken);
        if (key is null || !tokens.Verify(request.ApiKey, key.SecretDigest))
        {
            return new(false, null, [], null, "invalid");
        }

        if (!key.IsActive(clock.UtcNow))
        {
            return new(false, key.OrganizationId, [], key.Id, "expired_or_revoked");
        }

        if (!string.IsNullOrWhiteSpace(request.RequiredScope) && !key.Scopes.Contains(request.RequiredScope, StringComparer.Ordinal))
        {
            return new(false, key.OrganizationId, key.Scopes, key.Id, "missing_scope");
        }

        key.MarkUsed(clock.UtcNow);
        await apiKeys.SaveChangesAsync(cancellationToken);
        return new(true, key.OrganizationId, key.Scopes, key.Id, null);
    }
}
