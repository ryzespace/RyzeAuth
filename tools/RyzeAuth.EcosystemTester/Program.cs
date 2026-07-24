using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RyzeAuth.EcosystemTester;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = TesterOptions.Parse(args);
            if (options.ShowHelp)
            {
                Console.WriteLine(TesterOptions.Help);
                return 0;
            }

            var runner = new EcosystemTestRunner(options);
            var report = await runner.RunAsync();
            var json = JsonSerializer.Serialize(report, JsonOptions);
            if (string.IsNullOrWhiteSpace(options.ReportPath))
            {
                Console.WriteLine(json);
            }
            else
            {
                var directory = Path.GetDirectoryName(options.ReportPath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                await File.WriteAllTextAsync(options.ReportPath, json + Environment.NewLine);
                Console.WriteLine($"Report written to {options.ReportPath}");
                Console.WriteLine($"{report.PassedCount}/{report.Results.Count} checks passed; {report.FailedCount} failed; {report.WarningCount} warnings.");
            }

            return report.FailedCount == 0 ? 0 : 1;
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"Configuration error: {exception.Message}");
            Console.Error.WriteLine(TesterOptions.Help);
            return 2;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Tester failed unexpectedly: {exception.GetType().Name}: {exception.Message}");
            return 3;
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };
}

internal sealed class EcosystemTestRunner(TesterOptions options)
{
    private readonly HttpClient _client = CreateHttpClient(options);
    private readonly List<CheckResult> _results = [];

    public async Task<TestReport> RunAsync()
    {
        await RunCheckAsync("configuration.https", ValidateTransportAsync);
        await RunCheckAsync("keycloak.discovery", CheckDiscoveryAsync);
        await RunCheckAsync("keycloak.jwks", CheckJwksAsync);
        await RunCheckAsync("api.liveness", CheckLivenessAsync);
        await RunCheckAsync("api.security-headers", CheckSecurityHeadersAsync);
        await RunCheckAsync("api.unauthenticated-protection", CheckUnauthenticatedProtectionAsync);
        await RunCheckAsync("api.cors-deny-untrusted-origin", CheckCorsAsync);

        if (!string.IsNullOrWhiteSpace(options.AccessToken))
        {
            await RunCheckAsync("jwt.access-token-shape", CheckAccessTokenShapeAsync);
        }

        if (options.ActiveChecks)
        {
            await RunCheckAsync("api.password-reset-enumeration", CheckPasswordResetUniformResponseAsync);
        }

        if (options.ConfirmRateLimit)
        {
            await RunCheckAsync("api.password-reset-rate-limit", CheckPasswordResetRateLimitAsync);
        }

        return new TestReport(
            StartedAtUtc: _startedAt,
            FinishedAtUtc: DateTimeOffset.UtcNow,
            ApiBaseUrl: options.ApiBaseUrl.ToString(),
            Authority: options.Authority.ToString(),
            Results: _results);
    }

    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;

    private async Task RunCheckAsync(string name, Func<Task<CheckOutcome>> check)
    {
        var started = DateTimeOffset.UtcNow;
        try
        {
            var outcome = await check();
            _results.Add(new CheckResult(name, outcome.Status, outcome.Message, started, DateTimeOffset.UtcNow));
        }
        catch (HttpRequestException exception)
        {
            _results.Add(new CheckResult(name, CheckStatus.Fail, $"HTTP request failed: {exception.Message}", started, DateTimeOffset.UtcNow));
        }
        catch (JsonException exception)
        {
            _results.Add(new CheckResult(name, CheckStatus.Fail, $"Invalid JSON contract: {exception.Message}", started, DateTimeOffset.UtcNow));
        }
        catch (Exception exception)
        {
            _results.Add(new CheckResult(name, CheckStatus.Fail, $"Unexpected {exception.GetType().Name}: {exception.Message}", started, DateTimeOffset.UtcNow));
        }
    }

    private Task<CheckOutcome> ValidateTransportAsync()
    {
        if (options.AllowHttp)
        {
            return Task.FromResult(CheckOutcome.Pass("HTTP explicitly allowed for an isolated local environment."));
        }

        if (options.ApiBaseUrl.Scheme != Uri.UriSchemeHttps || options.Authority.Scheme != Uri.UriSchemeHttps)
        {
            return Task.FromResult(CheckOutcome.Fail("Both --api and --authority must use HTTPS. Use --allow-http only for an isolated local stack."));
        }

        return Task.FromResult(CheckOutcome.Pass("API and Keycloak authority use HTTPS."));
    }

    private async Task<CheckOutcome> CheckDiscoveryAsync()
    {
        using var response = await _client.GetAsync(new Uri(options.Authority, ".well-known/openid-configuration"));
        if (!response.IsSuccessStatusCode)
        {
            return CheckOutcome.Fail($"Discovery returned HTTP {(int)response.StatusCode}.");
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        var issuer = RequiredString(root, "issuer");
        if (!UriEquals(issuer, options.Authority.ToString()))
        {
            return CheckOutcome.Fail("Discovery issuer does not exactly match the configured authority.");
        }

        EnsureSecureEndpoint(RequiredString(root, "authorization_endpoint"), "authorization_endpoint");
        EnsureSecureEndpoint(RequiredString(root, "token_endpoint"), "token_endpoint");
        EnsureSecureEndpoint(RequiredString(root, "jwks_uri"), "jwks_uri");

        if (!root.TryGetProperty("code_challenge_methods_supported", out var pkce)
            || !pkce.EnumerateArray().Any(item => item.GetString() == "S256"))
        {
            return CheckOutcome.Fail("OIDC discovery does not advertise S256 PKCE.");
        }

        return CheckOutcome.Pass("OIDC discovery has matching issuer, secure endpoints and S256 PKCE.");
    }

    private async Task<CheckOutcome> CheckJwksAsync()
    {
        using var discoveryResponse = await _client.GetAsync(new Uri(options.Authority, ".well-known/openid-configuration"));
        discoveryResponse.EnsureSuccessStatusCode();
        using var discovery = JsonDocument.Parse(await discoveryResponse.Content.ReadAsStringAsync());
        var jwksUri = new Uri(RequiredString(discovery.RootElement, "jwks_uri"));
        using var jwksResponse = await _client.GetAsync(jwksUri);
        if (!jwksResponse.IsSuccessStatusCode)
        {
            return CheckOutcome.Fail($"JWKS returned HTTP {(int)jwksResponse.StatusCode}.");
        }

        using var jwks = JsonDocument.Parse(await jwksResponse.Content.ReadAsStringAsync());
        if (!jwks.RootElement.TryGetProperty("keys", out var keys) || keys.GetArrayLength() == 0)
        {
            return CheckOutcome.Fail("JWKS does not contain signing keys.");
        }

        var supported = new HashSet<string>(StringComparer.Ordinal) { "RSA", "EC", "OKP" };
        var algorithms = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys.EnumerateArray())
        {
            var keyId = RequiredString(key, "kid");
            var type = RequiredString(key, "kty");
            var use = key.TryGetProperty("use", out var useProperty) ? useProperty.GetString() : null;
            var algorithm = key.TryGetProperty("alg", out var algorithmProperty) ? algorithmProperty.GetString() : null;
            if (string.IsNullOrWhiteSpace(keyId) || !supported.Contains(type))
            {
                return CheckOutcome.Fail("JWKS exposes an invalid kid or unsupported key type.");
            }

            if (string.Equals(use, "sig", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(algorithm))
            {
                algorithms.Add(algorithm);
            }

            if (algorithm?.StartsWith("HS", StringComparison.Ordinal) == true || type == "oct")
            {
                return CheckOutcome.Fail("JWKS exposes a symmetric/HMAC signing key; RyzeAuth services must not trust shared HS algorithms.");
            }
        }

        if (algorithms.Count == 0)
        {
            return CheckOutcome.Fail("JWKS has no signing algorithm metadata.");
        }

        var preferred = algorithms.Overlaps(["EdDSA", "ES256", "RS256"]);
        return preferred
            ? CheckOutcome.Pass($"JWKS has {keys.GetArrayLength()} asymmetric key(s), with supported signing algorithm(s): {string.Join(", ", algorithms)}.")
            : CheckOutcome.Warn($"JWKS is asymmetric but does not advertise EdDSA, ES256 or RS256 (advertised: {string.Join(", ", algorithms)}).");
    }

    private async Task<CheckOutcome> CheckLivenessAsync()
    {
        using var response = await _client.GetAsync(new Uri(options.ApiBaseUrl, "health/live"));
        return response.StatusCode == HttpStatusCode.OK
            ? CheckOutcome.Pass("Liveness endpoint returned HTTP 200.")
            : CheckOutcome.Fail($"Liveness endpoint returned HTTP {(int)response.StatusCode}.");
    }

    private async Task<CheckOutcome> CheckSecurityHeadersAsync()
    {
        using var response = await _client.GetAsync(new Uri(options.ApiBaseUrl, "openapi/v1.json"));
        if (!response.IsSuccessStatusCode)
        {
            return CheckOutcome.Fail($"OpenAPI endpoint returned HTTP {(int)response.StatusCode}; cannot inspect API headers.");
        }

        var required = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Security-Policy"] = "default-src 'none'",
            ["X-Content-Type-Options"] = "nosniff",
            ["X-Frame-Options"] = "DENY",
            ["Referrer-Policy"] = "no-referrer",
            ["Permissions-Policy"] = ""
        };
        foreach (var (header, expectedValue) in required)
        {
            if (!response.Headers.TryGetValues(header, out var values) || !values.Any(value => value.Contains(expectedValue, StringComparison.OrdinalIgnoreCase)))
            {
                return CheckOutcome.Fail($"Missing or unsafe {header} header.");
            }
        }

        if (options.ApiBaseUrl.Scheme == Uri.UriSchemeHttps
            && (!response.Headers.TryGetValues("Strict-Transport-Security", out var hsts) || !hsts.Any(value => value.Contains("max-age=", StringComparison.OrdinalIgnoreCase))))
        {
            return CheckOutcome.Fail("HTTPS API response does not have Strict-Transport-Security.");
        }

        return CheckOutcome.Pass("Required CSP, framing, content-type, referrer, permissions and transport headers are present.");
    }

    private async Task<CheckOutcome> CheckUnauthenticatedProtectionAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(options.ApiBaseUrl, "v1/organizations"))
        {
            Content = JsonContent("{\"slug\":\"black-box-probe\",\"displayName\":\"Black box probe\"}")
        };
        using var response = await _client.SendAsync(request);
        return response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
            ? CheckOutcome.Pass("Protected organization endpoint rejects unauthenticated requests.")
            : CheckOutcome.Fail($"Protected organization endpoint returned HTTP {(int)response.StatusCode}, expected 401/403.");
    }

    private async Task<CheckOutcome> CheckCorsAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, new Uri(options.ApiBaseUrl, "v1/organizations"));
        request.Headers.Add("Origin", "https://untrusted.invalid");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        using var response = await _client.SendAsync(request);
        if (response.Headers.TryGetValues("Access-Control-Allow-Origin", out var origins) && origins.Any(origin => origin is "*" or "https://untrusted.invalid"))
        {
            return CheckOutcome.Fail("API grants CORS access to an untrusted origin.");
        }

        return CheckOutcome.Pass("API does not grant CORS access to an untrusted origin.");
    }

    private async Task<CheckOutcome> CheckPasswordResetUniformResponseAsync()
    {
        var email = $"ryzeauth-blackbox-{RandomNumberGenerator.GetHexString(12)}@invalid.example";
        using var response = await SendPasswordResetAsync(email);
        return response.StatusCode == HttpStatusCode.Accepted
            ? CheckOutcome.Pass("Unknown-account password-reset request returns uniform HTTP 202 response.")
            : CheckOutcome.Fail($"Unknown-account password-reset request returned HTTP {(int)response.StatusCode}, expected 202.");
    }

    private async Task<CheckOutcome> CheckPasswordResetRateLimitAsync()
    {
        var email = $"ryzeauth-rate-limit-{RandomNumberGenerator.GetHexString(12)}@invalid.example";
        var statuses = new List<int>();
        for (var attempt = 0; attempt < 6; attempt++)
        {
            using var response = await SendPasswordResetAsync(email);
            statuses.Add((int)response.StatusCode);
        }

        if (statuses.Take(5).All(status => status == (int)HttpStatusCode.Accepted) && statuses[5] == (int)HttpStatusCode.TooManyRequests)
        {
            return CheckOutcome.Pass("Password-reset endpoint enforces 5 requests per IP / 15 minutes.");
        }

        return CheckOutcome.Fail($"Unexpected reset rate-limit sequence: {string.Join(",", statuses)}. This check consumes the tester IP budget for 15 minutes.");
    }

    private Task<CheckOutcome> CheckAccessTokenShapeAsync()
    {
        var segments = options.AccessToken!.Split('.');
        if (segments.Length != 3)
        {
            return Task.FromResult(CheckOutcome.Fail("--access-token is not a compact JWT."));
        }

        using var header = JsonDocument.Parse(Base64UrlDecode(segments[0]));
        using var payload = JsonDocument.Parse(Base64UrlDecode(segments[1]));
        var algorithm = RequiredString(header.RootElement, "alg");
        if (algorithm.StartsWith("HS", StringComparison.Ordinal) || algorithm == "none")
        {
            return Task.FromResult(CheckOutcome.Fail("Access token uses prohibited symmetric or unsigned JWT algorithm."));
        }

        var issuedAt = RequiredInt64(payload.RootElement, "iat");
        var expiresAt = RequiredInt64(payload.RootElement, "exp");
        if (expiresAt <= issuedAt || expiresAt - issuedAt > 900)
        {
            return Task.FromResult(CheckOutcome.Fail("Access token lifetime is not within the required 5–15 minute window."));
        }

        if (!payload.RootElement.TryGetProperty("iss", out var issuer) || !UriEquals(issuer.GetString(), options.Authority.ToString()))
        {
            return Task.FromResult(CheckOutcome.Fail("Access token issuer does not match configured Keycloak authority."));
        }

        return Task.FromResult(CheckOutcome.Pass($"Access token uses {algorithm} and has a {(expiresAt - issuedAt) / 60}-minute lifetime. Token content was not logged."));
    }

    private async Task<HttpResponseMessage> SendPasswordResetAsync(string email)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(options.ApiBaseUrl, "v1/password-resets"))
        {
            Content = JsonContent(JsonSerializer.Serialize(new { email }))
        };
        return await _client.SendAsync(request);
    }

    private void EnsureSecureEndpoint(string endpoint, string name)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"Discovery {name} is not an absolute URI.");
        }

        if (!options.AllowHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException($"Discovery {name} is not HTTPS.");
        }
    }

    private static HttpClient CreateHttpClient(TesterOptions options)
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds),
            DefaultRequestHeaders = { UserAgent = { new ProductInfoHeaderValue("RyzeAuthEcosystemTester", "1.0") } }
        };
        return client;
    }

    private static StringContent JsonContent(string value) => new(value, Encoding.UTF8, "application/json");
    private static string RequiredString(JsonElement element, string property) => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
        ? value.GetString()!
        : throw new InvalidOperationException($"Required JSON property '{property}' is missing.");
    private static long RequiredInt64(JsonElement element, string property) => element.TryGetProperty(property, out var value) && value.TryGetInt64(out var number)
        ? number
        : throw new InvalidOperationException($"Required numeric JWT property '{property}' is missing.");
    private static bool UriEquals(string? first, string second) => string.Equals(first?.TrimEnd('/'), second.TrimEnd('/'), StringComparison.Ordinal);
    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }
}

internal sealed record TesterOptions(
    Uri ApiBaseUrl,
    Uri Authority,
    bool AllowHttp,
    bool ActiveChecks,
    bool ConfirmRateLimit,
    int TimeoutSeconds,
    string? ReportPath,
    string? AccessToken,
    bool ShowHelp)
{
    public const string Help = """
RyzeAuth Ecosystem Tester — independent black-box console verifier

Usage:
  dotnet run --project tools/RyzeAuth.EcosystemTester -- [options]

Required (or environment equivalents):
  --api <url>               API base URL (RYZEAUTH_TEST_API_BASE_URL)
  --authority <url>         Keycloak realm URL (RYZEAUTH_TEST_AUTHORITY)

Options:
  --allow-http              Allow HTTP only for an isolated local Compose stack.
  --active                  Execute one harmless password-reset enumeration check using a random @invalid.example address.
  --confirm-rate-limit      Execute six reset requests; verifies 5/IP/15 min and consumes this tester IP budget.
  --access-token <jwt>      Validate JWT shape, non-HS algorithm, issuer and <=15 min lifetime. Never printed.
  --report <path>           Write JSON report to a file instead of stdout.
  --timeout <seconds>       HTTP timeout, 1–60 seconds (default 10).
  --help                    Show this help.

The program has no ProjectReference, no database connection and no package dependency. It exercises only public HTTP/OIDC contracts.
""";

    public static TesterOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument is "--help" or "-h" or "--allow-http" or "--active" or "--confirm-rate-limit")
            {
                flags.Add(argument);
                continue;
            }

            if (argument is "--api" or "--authority" or "--access-token" or "--report" or "--timeout")
            {
                if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"{argument} requires a value.");
                }

                values[argument] = args[++index];
                continue;
            }

            throw new ArgumentException($"Unknown option '{argument}'.");
        }

        if (flags.Contains("--help") || flags.Contains("-h"))
        {
            return new TesterOptions(new Uri("https://invalid.example/"), new Uri("https://invalid.example/"), false, false, false, 10, null, null, true);
        }

        var api = values.GetValueOrDefault("--api") ?? Environment.GetEnvironmentVariable("RYZEAUTH_TEST_API_BASE_URL");
        var authority = values.GetValueOrDefault("--authority") ?? Environment.GetEnvironmentVariable("RYZEAUTH_TEST_AUTHORITY");
        if (!Uri.TryCreate(api, UriKind.Absolute, out var apiUri) || !Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri))
        {
            throw new ArgumentException("Provide absolute --api and --authority URLs, or set RYZEAUTH_TEST_API_BASE_URL and RYZEAUTH_TEST_AUTHORITY.");
        }

        var timeout = 10;
        if (values.TryGetValue("--timeout", out var rawTimeout) && (!int.TryParse(rawTimeout, out timeout) || timeout is < 1 or > 60))
        {
            throw new ArgumentException("--timeout must be an integer from 1 to 60.");
        }

        var active = flags.Contains("--active") || flags.Contains("--confirm-rate-limit");
        return new TesterOptions(
            EnsureTrailingSlash(apiUri),
            EnsureTrailingSlash(authorityUri),
            flags.Contains("--allow-http"),
            active,
            flags.Contains("--confirm-rate-limit"),
            timeout,
            values.GetValueOrDefault("--report"),
            values.GetValueOrDefault("--access-token") ?? Environment.GetEnvironmentVariable("RYZEAUTH_TEST_ACCESS_TOKEN"),
            false);
    }

    private static Uri EnsureTrailingSlash(Uri value) => value.AbsoluteUri.EndsWith('/') ? value : new Uri(value.AbsoluteUri + "/", UriKind.Absolute);
}

internal enum CheckStatus { Pass, Fail, Warning }
internal sealed record CheckOutcome(CheckStatus Status, string Message)
{
    public static CheckOutcome Pass(string message) => new(CheckStatus.Pass, message);
    public static CheckOutcome Fail(string message) => new(CheckStatus.Fail, message);
    public static CheckOutcome Warn(string message) => new(CheckStatus.Warning, message);
}

internal sealed record CheckResult(string Name, CheckStatus Status, string Message, DateTimeOffset StartedAtUtc, DateTimeOffset FinishedAtUtc);
internal sealed record TestReport(DateTimeOffset StartedAtUtc, DateTimeOffset FinishedAtUtc, string ApiBaseUrl, string Authority, IReadOnlyList<CheckResult> Results)
{
    public int PassedCount => Results.Count(result => result.Status == CheckStatus.Pass);
    public int FailedCount => Results.Count(result => result.Status == CheckStatus.Fail);
    public int WarningCount => Results.Count(result => result.Status == CheckStatus.Warning);
}
