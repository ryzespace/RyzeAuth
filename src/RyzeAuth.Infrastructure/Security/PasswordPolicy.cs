using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Security;

public sealed class HttpsPasswordPolicy(HttpClient httpClient, IOptions<SecurityOptions> security, ILogger<HttpsPasswordPolicy> logger) : IPasswordPolicy
{
    private static readonly Action<ILogger, Exception?> LogHibpLookupFailure = LoggerMessage.Define(
        LogLevel.Warning, new EventId(1002, "HibpLookupFailure"), "HIBP range lookup failed; no password value or hash is logged.");
    private static readonly HashSet<string> BannedPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "password123", "qwertyuiop", "123456789012", "letmeinletmein", "adminadminadmin", "ryzespace"
    };

    public async Task<PasswordPolicyResult> ValidateAsync(string password, string? userName, CancellationToken cancellationToken)
    {
        var errors = new List<string>();
        if (password.Length < 12)
        {
            errors.Add("Password must be at least 12 characters long.");
        }

        if (BannedPasswords.Contains(password) || (!string.IsNullOrWhiteSpace(userName) && password.Contains(userName, StringComparison.OrdinalIgnoreCase)))
        {
            errors.Add("Choose a password that is not common and does not contain your username.");
        }

        try
        {
            if (await IsPwnedAsync(password, cancellationToken))
            {
                errors.Add("This password appears in a known breach. Choose another password.");
            }
        }
        catch (HttpRequestException exception)
        {
            LogHibpLookupFailure(logger, exception);
            if (security.Value.RequireBreachCheck)
            {
                errors.Add("Password breach check is currently unavailable. Try again shortly.");
            }
        }

        return errors.Count == 0 ? PasswordPolicyResult.Success : new PasswordPolicyResult(false, errors);
    }

    private async Task<bool> IsPwnedAsync(string password, CancellationToken cancellationToken)
    {
#pragma warning disable CA5350
        var full = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
#pragma warning restore CA5350
        var prefix = full[..5];
        var suffix = full[5..];
        using var request = new HttpRequestMessage(HttpMethod.Get, $"range/{prefix}");
        request.Headers.Add("Add-Padding", "true");
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        return body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split(':', 2)[0])
            .Any(candidate => candidate.Equals(suffix, StringComparison.OrdinalIgnoreCase));
    }
}
