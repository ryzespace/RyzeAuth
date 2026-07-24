using System.Net.Mail;
using System.Security.Claims;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Api.Endpoints;

public static class ScimEndpoints
{
    private const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    private const string ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    public static IEndpointRouteBuilder MapScimEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/scim/v2").WithTags("SCIM 2.0");
        group.MapGet("/Users", FindUsers).RequireAuthorization("ScimRead");
        group.MapGet("/Users/{subjectId}", GetUser).RequireAuthorization("ScimRead");
        group.MapPost("/Users", CreateUser).RequireAuthorization("ScimWrite");
        group.MapPut("/Users/{subjectId}", ReplaceUser).RequireAuthorization("ScimWrite");
        group.MapDelete("/Users/{subjectId}", DisableUser).RequireAuthorization("ScimWrite");
        return endpoints;
    }

    private static async Task<IResult> FindUsers(
        string? filter,
        IKeycloakAdminClient keycloak,
        CancellationToken cancellationToken)
    {
        var email = FilterEmail(filter);
        if (email is null)
        {
            return Results.Ok(new ScimListResponse([UserSchema, ListSchema], 0, 0, 1, []));
        }

        var user = await keycloak.FindUserByEmailAsync(email, cancellationToken);
        var resources = user is null ? [] : new[] { ToResponse(user, null) };
        return Results.Ok(new ScimListResponse([UserSchema, ListSchema], resources.Length, 0, 1, resources));
    }

    private static async Task<IResult> GetUser(string subjectId, IKeycloakAdminClient keycloak, CancellationToken cancellationToken)
    {
        var user = await keycloak.GetUserAsync(subjectId, cancellationToken);
        return user is null ? Results.NotFound() : Results.Ok(ToResponse(user, null));
    }

    private static async Task<IResult> CreateUser(
        ScimUserRequest request,
        ClaimsPrincipal principal,
        IKeycloakAdminClient keycloak,
        IAuditTrail auditTrail,
        IClock clock,
        CancellationToken cancellationToken)
    {
        var email = Email(request);
        if (email is null)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["userName"] = ["A valid userName or primary email is required."] });
        }

        if (await keycloak.FindUserByEmailAsync(email, cancellationToken) is not null)
        {
            return Results.Conflict();
        }

        var user = await keycloak.CreateUserAsync(new KeycloakUserCreateRequest(
            email,
            request.Name?.GivenName,
            request.Name?.FamilyName,
            request.Active ?? true,
            request.ExternalId), cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("scim.user.created", "success", clock.UtcNow,
            Actor(principal), metadataJson: "{\"targetSubject\":\"" + user.SubjectId + "\"}"), cancellationToken);
        return Results.Created($"/scim/v2/Users/{user.SubjectId}", ToResponse(user, request.ExternalId));
    }

    private static async Task<IResult> ReplaceUser(
        string subjectId,
        ScimUserRequest request,
        ClaimsPrincipal principal,
        IKeycloakAdminClient keycloak,
        IAuditTrail auditTrail,
        IClock clock,
        CancellationToken cancellationToken)
    {
        if (await keycloak.GetUserAsync(subjectId, cancellationToken) is null)
        {
            return Results.NotFound();
        }

        var email = Email(request);
        if (email is null)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["userName"] = ["A valid userName or primary email is required."] });
        }

        await keycloak.UpdateUserAsync(subjectId, new KeycloakUserUpdateRequest(
            email,
            request.Name?.GivenName,
            request.Name?.FamilyName,
            request.Active ?? true,
            request.ExternalId), cancellationToken);
        var user = await keycloak.GetUserAsync(subjectId, cancellationToken)
            ?? throw new InvalidOperationException("Keycloak user disappeared after update.");
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("scim.user.updated", "success", clock.UtcNow,
            Actor(principal), metadataJson: "{\"targetSubject\":\"" + subjectId + "\"}"), cancellationToken);
        return Results.Ok(ToResponse(user, request.ExternalId));
    }

    private static async Task<IResult> DisableUser(
        string subjectId,
        ClaimsPrincipal principal,
        IKeycloakAdminClient keycloak,
        IAuditTrail auditTrail,
        IClock clock,
        CancellationToken cancellationToken)
    {
        if (await keycloak.GetUserAsync(subjectId, cancellationToken) is null)
        {
            return Results.NotFound();
        }

        await keycloak.DisableUserAsync(subjectId, cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("scim.user.deprovisioned", "success", clock.UtcNow,
            Actor(principal), metadataJson: "{\"targetSubject\":\"" + subjectId + "\"}"), cancellationToken);
        return Results.NoContent();
    }

    private static ScimUserResponse ToResponse(KeycloakUser user, string? externalId) => new(
        [UserSchema],
        user.SubjectId,
        user.Email,
        externalId,
        user.Enabled,
        [new ScimEmail(user.Email, "work", true)]);

    private static string? FilterEmail(string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return null;
        }

        var parts = filter.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 3 || !string.Equals(parts[0], "userName", StringComparison.OrdinalIgnoreCase) || !string.Equals(parts[1], "eq", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return IsEmail(parts[2].Trim('"')) ? parts[2].Trim('"') : null;
    }

    private static string? Email(ScimUserRequest request)
    {
        if (IsEmail(request.UserName))
        {
            return request.UserName;
        }

        if (request.Emails is null)
        {
            return null;
        }

        string? fallback = null;
        foreach (var candidate in request.Emails)
        {
            fallback ??= candidate.Value;
            if (candidate.Primary == true)
            {
                return IsEmail(candidate.Value) ? candidate.Value : null;
            }
        }

        return IsEmail(fallback) ? fallback : null;
    }

    private static bool IsEmail(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            _ = new MailAddress(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string? Actor(ClaimsPrincipal principal) => principal.FindFirstValue("sub");

    public sealed record ScimUserRequest(string? UserName, string? ExternalId, ScimName? Name, bool? Active, IReadOnlyList<ScimEmail>? Emails);
    public sealed record ScimName(string? GivenName, string? FamilyName);
    public sealed record ScimEmail(string Value, string? Type, bool? Primary);
    public sealed record ScimUserResponse(IReadOnlyList<string> Schemas, string Id, string UserName, string? ExternalId, bool Active, IReadOnlyList<ScimEmail> Emails);
    public sealed record ScimListResponse(IReadOnlyList<string> Schemas, int TotalResults, int StartIndex, int ItemsPerPage, IReadOnlyList<ScimUserResponse> Resources);
}
