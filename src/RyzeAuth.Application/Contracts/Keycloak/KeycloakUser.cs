using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record KeycloakUser(string SubjectId, string Email, bool EmailVerified, bool Enabled);
