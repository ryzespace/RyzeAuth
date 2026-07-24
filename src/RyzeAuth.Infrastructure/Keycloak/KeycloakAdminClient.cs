using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Keycloak;

public sealed class KeycloakAdminClient(
    HttpClient httpClient,
    IOptions<KeycloakOptions> options,
    IMemoryCache cache) : IKeycloakAdminClient
{
    private readonly KeycloakOptions _options = options.Value;

    public async Task<KeycloakUser?> FindUserByEmailAsync(string email, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users?email={Uri.EscapeDataString(email)}&exact=true");
        await AuthorizeAsync(request, cancellationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var users = await response.Content.ReadFromJsonAsync<List<KeycloakUserResponse>>(cancellationToken: cancellationToken) ?? [];
        var user = users.SingleOrDefault(x => string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase));
        return ToUser(user);
    }

    public async Task<KeycloakUser?> GetUserAsync(string subjectId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users/{Uri.EscapeDataString(subjectId)}");
        await AuthorizeAsync(request, cancellationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var user = await response.Content.ReadFromJsonAsync<KeycloakUserResponse>(cancellationToken: cancellationToken);
        return ToUser(user);
    }

    public async Task<KeycloakUser> CreateUserAsync(KeycloakUserCreateRequest request, CancellationToken cancellationToken)
    {
        var attributes = string.IsNullOrWhiteSpace(request.ExternalId)
            ? null
            : new Dictionary<string, string[]> { ["externalId"] = [request.ExternalId] };
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users")
        {
            Content = JsonContent.Create(new
            {
                username = request.Email,
                email = request.Email,
                firstName = request.FirstName,
                lastName = request.LastName,
                enabled = request.Enabled,
                emailVerified = false,
                attributes
            })
        };
        await AuthorizeAsync(httpRequest, cancellationToken);
        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        response.EnsureSuccessStatusCode();
        var location = response.Headers.Location?.ToString();
        var createdId = string.IsNullOrWhiteSpace(location) ? null : location.TrimEnd('/').Split('/').LastOrDefault();
        var created = createdId is null ? null : await GetUserAsync(createdId, cancellationToken);
        return created ?? await FindUserByEmailAsync(request.Email, cancellationToken)
            ?? throw new InvalidOperationException("Keycloak created a user but did not return a readable representation.");
    }

    public async Task UpdateUserAsync(string subjectId, KeycloakUserUpdateRequest request, CancellationToken cancellationToken)
    {
        var attributes = string.IsNullOrWhiteSpace(request.ExternalId)
            ? null
            : new Dictionary<string, string[]> { ["externalId"] = [request.ExternalId] };
        using var httpRequest = new HttpRequestMessage(HttpMethod.Put,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users/{Uri.EscapeDataString(subjectId)}")
        {
            Content = JsonContent.Create(new
            {
                username = request.Email,
                email = request.Email,
                firstName = request.FirstName,
                lastName = request.LastName,
                enabled = request.Enabled,
                attributes
            })
        };
        await AuthorizeAsync(httpRequest, cancellationToken);
        using var response = await httpClient.SendAsync(httpRequest, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task DisableUserAsync(string subjectId, CancellationToken cancellationToken)
    {
        var user = await GetUserAsync(subjectId, cancellationToken)
            ?? throw new InvalidOperationException("Keycloak user does not exist.");
        await UpdateUserAsync(subjectId, new KeycloakUserUpdateRequest(user.Email, null, null, false, null), cancellationToken);
        await LogoutAllSessionsAsync(subjectId, cancellationToken);
    }

    public async Task<TokenIntrospectionResult> IntrospectAsync(string token, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = _options.AdminClientId,
            ["client_secret"] = _options.AdminClientSecret
        });
        using var response = await httpClient.PostAsync(
            $"realms/{Uri.EscapeDataString(_options.Realm)}/protocol/openid-connect/token/introspect", content, cancellationToken);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<TokenIntrospectionResponse>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Keycloak introspection endpoint returned no payload.");
        var scopes = string.IsNullOrWhiteSpace(payload.Scope)
            ? Array.Empty<string>()
            : payload.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return new TokenIntrospectionResult(
            payload.Active,
            payload.Subject,
            payload.ClientId,
            scopes,
            payload.ExpiresAt is null ? null : DateTimeOffset.FromUnixTimeSeconds(payload.ExpiresAt.Value));
    }

    public async Task ResetPasswordAsync(string subjectId, string newPassword, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users/{Uri.EscapeDataString(subjectId)}/reset-password")
        {
            Content = JsonContent.Create(new { type = "password", value = newPassword, temporary = false })
        };
        await AuthorizeAsync(request, cancellationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task LogoutSessionAsync(string keycloakSessionId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/sessions/{Uri.EscapeDataString(keycloakSessionId)}");
        await AuthorizeAsync(request, cancellationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode != System.Net.HttpStatusCode.NotFound)
        {
            response.EnsureSuccessStatusCode();
        }
    }

    public async Task LogoutAllSessionsAsync(string subjectId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"admin/realms/{Uri.EscapeDataString(_options.Realm)}/users/{Uri.EscapeDataString(subjectId)}/logout");
        await AuthorizeAsync(request, cancellationToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static KeycloakUser? ToUser(KeycloakUserResponse? user) => user is null || string.IsNullOrWhiteSpace(user.Id) || string.IsNullOrWhiteSpace(user.Email)
        ? null
        : new KeycloakUser(user.Id, user.Email, user.EmailVerified, user.Enabled);

    private async Task AuthorizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetAccessTokenAsync(cancellationToken));
    }

    private async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken)
    {
        const string cacheKey = "keycloak-admin-service-token";
        if (cache.TryGetValue<string>(cacheKey, out var existing) && !string.IsNullOrWhiteSpace(existing))
        {
            return existing;
        }

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _options.AdminClientId,
            ["client_secret"] = _options.AdminClientSecret
        });
        using var response = await httpClient.PostAsync(
            $"realms/{Uri.EscapeDataString(_options.Realm)}/protocol/openid-connect/token", content, cancellationToken);
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Keycloak token endpoint returned no token.");
        if (string.IsNullOrWhiteSpace(token.AccessToken))
        {
            throw new InvalidOperationException("Keycloak token endpoint returned an empty token.");
        }

        cache.Set(cacheKey, token.AccessToken, TimeSpan.FromSeconds(Math.Max(30, token.ExpiresIn - 30)));
        return token.AccessToken;
    }

    private sealed record TokenResponse([property: JsonPropertyName("access_token")] string AccessToken, [property: JsonPropertyName("expires_in")] int ExpiresIn);
    private sealed record TokenIntrospectionResponse(
        [property: JsonPropertyName("active")] bool Active,
        [property: JsonPropertyName("sub")] string? Subject,
        [property: JsonPropertyName("client_id")] string? ClientId,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("exp")] long? ExpiresAt);
    private sealed record KeycloakUserResponse(
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("email")] string? Email,
        [property: JsonPropertyName("emailVerified")] bool EmailVerified,
        [property: JsonPropertyName("enabled")] bool Enabled);
}
