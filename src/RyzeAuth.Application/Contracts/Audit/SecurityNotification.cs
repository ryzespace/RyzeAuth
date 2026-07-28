using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record SecurityNotification(string RecipientEmail, string EventType, DateTimeOffset OccurredAt, string? UserAgent, string? CountryCode);
