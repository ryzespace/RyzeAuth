using System.Security.Claims;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using RyzeAuth.Application;

namespace RyzeAuth.Api.Endpoints;

public static class RyzeAuthEndpoints
{
    public static IEndpointRouteBuilder MapRyzeAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var publicApi = endpoints.MapGroup("/v1").WithTags("RyzeAuth");
        publicApi.MapPost("/password-resets", RequestPasswordReset)
            .AllowAnonymous()
            .RequireRateLimiting("password-reset")
            .Produces(StatusCodes.Status202Accepted)
            .ProducesProblem(StatusCodes.Status429TooManyRequests);
        publicApi.MapPost("/password-resets/complete", CompletePasswordReset)
            .AllowAnonymous()
            .RequireRateLimiting("password-reset")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status400BadRequest);

        var protectedApi = endpoints.MapGroup("/v1").RequireAuthorization().WithTags("RyzeAuth");
        protectedApi.MapPost("/organizations", CreateOrganization).Produces<OrganizationResult>(StatusCodes.Status201Created);
        protectedApi.MapPost("/organizations/{organizationId:guid}/members", AddMember).RequireAuthorization("RecentAuthentication").Produces(StatusCodes.Status204NoContent);
        protectedApi.MapGet("/organizations/{organizationId:guid}/audit", GetOrganizationAudit).Produces<IReadOnlyList<SecurityAuditResult>>(StatusCodes.Status200OK);
        protectedApi.MapPost("/organizations/{organizationId:guid}/api-keys", CreateApiKey)
            .RequireAuthorization("RecentAuthentication")
            .Produces<CreateApiKeyResponse>(StatusCodes.Status201Created);
        protectedApi.MapDelete("/organizations/{organizationId:guid}/api-keys/{apiKeyId:guid}", RevokeApiKey)
            .RequireAuthorization("RecentAuthentication")
            .Produces(StatusCodes.Status204NoContent);
        protectedApi.MapGet("/me/security-history", GetMySecurityHistory).Produces<IReadOnlyList<SecurityAuditResult>>(StatusCodes.Status200OK);
        protectedApi.MapGet("/me/devices", GetMyDevices).Produces<IReadOnlyList<DeviceSessionResult>>(StatusCodes.Status200OK);
        protectedApi.MapPatch("/me/devices/{deviceId:guid}", UpdateDevice).RequireAuthorization("RecentAuthentication").Produces(StatusCodes.Status204NoContent);
        protectedApi.MapDelete("/me/devices/{deviceId:guid}", RevokeDevice).Produces(StatusCodes.Status204NoContent);
        protectedApi.MapPost("/me/tokens/revoke", RevokeCurrentToken).Produces(StatusCodes.Status204NoContent);
        protectedApi.MapPost("/me/sessions/revoke-all", RevokeAllSessions).Produces(StatusCodes.Status204NoContent);
        return endpoints;
    }

    private static async Task<IResult> RequestPasswordReset(
        PasswordResetRequest request,
        HttpContext context,
        ISender sender,
        IConfiguration configuration,
        IRequestRateLimiter rateLimiter,
        CancellationToken cancellationToken)
    {
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!await rateLimiter.TryAcquireAsync("password-reset", ipAddress, 5, TimeSpan.FromMinutes(15), cancellationToken))
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        var resetBaseUrl = configuration["Security:PublicResetBaseUrl"]
            ?? throw new InvalidOperationException("Security:PublicResetBaseUrl is missing.");
        await sender.Send(new RequestPasswordResetCommand(request.Email, ipAddress, new Uri(resetBaseUrl)), cancellationToken);
        return Results.Accepted();
    }

    private static async Task<IResult> CompletePasswordReset(
        CompletePasswordResetRequest request,
        HttpContext context,
        ISender sender,
        IRequestRateLimiter rateLimiter,
        CancellationToken cancellationToken)
    {
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!await rateLimiter.TryAcquireAsync("password-reset-complete", ipAddress, 5, TimeSpan.FromMinutes(15), cancellationToken))
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        await sender.Send(new CompletePasswordResetCommand(request.Token, request.NewPassword, request.UserName), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> CreateOrganization(CreateOrganizationRequest request, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        var result = await sender.Send(new CreateOrganizationCommand(request.Slug, request.DisplayName, Subject(user)), cancellationToken);
        return Results.Created($"/v1/organizations/{result.Id}", result);
    }

    private static async Task<IResult> AddMember(Guid organizationId, AddMemberRequest request, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        await sender.Send(new AddMemberCommand(organizationId, Subject(user), request.SubjectId, request.Role, request.AttributesJson ?? "{}"), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetOrganizationAudit(Guid organizationId, int? take, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        var events = await sender.Send(new GetOrganizationSecurityAuditQuery(organizationId, Subject(user), take ?? 50), cancellationToken);
        return Results.Ok(events);
    }

    private static async Task<IResult> GetMySecurityHistory(int? take, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        var events = await sender.Send(new GetMySecurityAuditQuery(Subject(user), take ?? 50), cancellationToken);
        return Results.Ok(events);
    }

    private static async Task<IResult> CreateApiKey(Guid organizationId, CreateApiKeyRequest request, ClaimsPrincipal user, ISender sender, HttpResponse response, CancellationToken cancellationToken)
    {
        var result = await sender.Send(new CreateApiKeyCommand(organizationId, Subject(user), request.Name, request.Scopes, request.ExpiresAt), cancellationToken);
        response.Headers.CacheControl = "no-store";
        return Results.Created($"/v1/organizations/{organizationId}/api-keys/{result.Id}", new CreateApiKeyResponse(result.Id, result.ApiKey, result.Prefix, result.ExpiresAt));
    }

    private static async Task<IResult> RevokeApiKey(Guid organizationId, Guid apiKeyId, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        await sender.Send(new RevokeApiKeyCommand(organizationId, apiKeyId, Subject(user)), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetMyDevices(ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        var devices = await sender.Send(new GetMyDevicesQuery(Subject(user)), cancellationToken);
        return Results.Ok(devices);
    }

    private static async Task<IResult> UpdateDevice(Guid deviceId, UpdateDeviceRequest request, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        await sender.Send(new UpdateDeviceCommand(Subject(user), deviceId, request.DisplayName, request.IsTrusted), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> RevokeDevice(Guid deviceId, ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        await sender.Send(new RevokeDeviceCommand(Subject(user), deviceId), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> RevokeCurrentToken(
        ClaimsPrincipal user,
        ITokenBlacklistService blacklist,
        IAuditTrail auditTrail,
        RyzeAuth.Domain.IClock clock,
        CancellationToken cancellationToken)
    {
        var tokenId = user.FindFirstValue("jti");
        var expiresAt = TokenExpiration(user);
        if (string.IsNullOrWhiteSpace(tokenId) || expiresAt is null)
        {
            return Results.Problem("The access token does not contain jti and exp claims.", statusCode: StatusCodes.Status400BadRequest);
        }

        await blacklist.RevokeTokenAsync(tokenId, expiresAt.Value, cancellationToken);
        await auditTrail.RecordAsync(RyzeAuth.Domain.SecurityAuditEvent.Create("token.revoked", "success", clock.UtcNow, Subject(user)), cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> RevokeAllSessions(ClaimsPrincipal user, ISender sender, CancellationToken cancellationToken)
    {
        await sender.Send(new RevokeAllMySessionsCommand(Subject(user), user.FindFirstValue("jti"), TokenExpiration(user)), cancellationToken);
        return Results.NoContent();
    }

    private static DateTimeOffset? TokenExpiration(ClaimsPrincipal user) => long.TryParse(user.FindFirstValue("exp"), out var seconds)
        ? DateTimeOffset.FromUnixTimeSeconds(seconds)
        : null;

    private static string Subject(ClaimsPrincipal user) => user.FindFirstValue("sub")
        ?? throw new UnauthorizedAccessException("The access token does not contain a subject claim.");

    public sealed record PasswordResetRequest(string Email);
    public sealed record CompletePasswordResetRequest(string Token, string NewPassword, string? UserName);
    public sealed record CreateOrganizationRequest(string Slug, string DisplayName);
    public sealed record AddMemberRequest(string SubjectId, string Role, string? AttributesJson);
    public sealed record CreateApiKeyRequest(string Name, IReadOnlyList<string> Scopes, DateTimeOffset? ExpiresAt);
    public sealed record CreateApiKeyResponse(Guid Id, string ApiKey, string Prefix, DateTimeOffset? ExpiresAt);
    public sealed record UpdateDeviceRequest(string? DisplayName, bool? IsTrusted);
}
