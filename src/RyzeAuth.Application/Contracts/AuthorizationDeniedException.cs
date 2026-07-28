using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed class AuthorizationDeniedException(string message) : Exception(message);
