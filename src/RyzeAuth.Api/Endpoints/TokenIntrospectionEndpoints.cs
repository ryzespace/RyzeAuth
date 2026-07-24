using RyzeAuth.Application;

namespace RyzeAuth.Api.Endpoints;

public static class TokenIntrospectionEndpoints
{
    public static IEndpointRouteBuilder MapTokenIntrospectionEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/internal/tokens/introspect", Introspect)
            .WithTags("Internal Tokens")
            .RequireAuthorization("InternalService")
            .Produces<TokenIntrospectionResult>(StatusCodes.Status200OK);
        return endpoints;
    }

    private static async Task<IResult> Introspect(TokenIntrospectionRequest request, IKeycloakAdminClient keycloak, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || request.Token.Length > 16_384)
        {
            return Results.BadRequest();
        }

        var result = await keycloak.IntrospectAsync(request.Token, cancellationToken);
        return Results.Ok(result);
    }

    public sealed record TokenIntrospectionRequest(string Token);
}
