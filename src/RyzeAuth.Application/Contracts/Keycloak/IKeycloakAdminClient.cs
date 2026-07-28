using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IKeycloakAdminClient
{
    Task<KeycloakUser?> FindUserByEmailAsync(string email, CancellationToken cancellationToken);
    Task<KeycloakUser?> GetUserAsync(string subjectId, CancellationToken cancellationToken);
    Task<KeycloakUser> CreateUserAsync(KeycloakUserCreateRequest request, CancellationToken cancellationToken);
    Task UpdateUserAsync(string subjectId, KeycloakUserUpdateRequest request, CancellationToken cancellationToken);
    Task DisableUserAsync(string subjectId, CancellationToken cancellationToken);
    Task<TokenIntrospectionResult> IntrospectAsync(string token, CancellationToken cancellationToken);
    Task ResetPasswordAsync(string subjectId, string newPassword, CancellationToken cancellationToken);
    Task LogoutSessionAsync(string keycloakSessionId, CancellationToken cancellationToken);
    Task LogoutAllSessionsAsync(string subjectId, CancellationToken cancellationToken);
}
