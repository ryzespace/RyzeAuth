using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record KeycloakUserCreateRequest(
    string Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    string? ExternalId);
