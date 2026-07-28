using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed class SecurityValidationException(string message) : Exception(message);
