using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed class NotFoundException(string message) : Exception(message);
