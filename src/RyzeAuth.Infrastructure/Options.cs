namespace RyzeAuth.Infrastructure;

public sealed class KeycloakOptions
{
    public const string SectionName = "Keycloak";
    public required string Authority { get; init; }
    public required string AdminBaseUrl { get; init; }
    public required string Realm { get; init; }
    public required string AdminClientId { get; init; }
    public required string AdminClientSecret { get; init; }
    public string ValidAudience { get; init; } = "ryzeauth-api";
}

public sealed class SecurityOptions
{
    public const string SectionName = "Security";
    public required string TokenDigestKey { get; init; }
    public required string KeycloakEventSigningKey { get; init; }
    public string PublicResetBaseUrl { get; init; } = "https://auth.ryzespace.example/reset-password";
    public bool RequireBreachCheck { get; init; } = true;
    public int MaximumDevicesPerUser { get; init; } = 5;

    public static bool IsValidTokenDigestKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            return Convert.FromBase64String(value).Length >= 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public sealed class SmtpOptions
{
    public const string SectionName = "Smtp";
    public bool Enabled { get; init; }
    public string Host { get; init; } = "";
    public int Port { get; init; } = 587;
    public string UserName { get; init; } = "";
    public string Password { get; init; } = "";
    public string From { get; init; } = "security@ryzespace.example";
}
