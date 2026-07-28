using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record KeycloakUserUpdateRequest(
    string Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    string? ExternalId);
