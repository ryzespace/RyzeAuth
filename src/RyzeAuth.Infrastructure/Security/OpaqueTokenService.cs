using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Security;

public sealed class OpaqueTokenService(IOptions<SecurityOptions> options) : IOpaqueTokenService
{
    private readonly byte[] _key = DecodeKey(options.Value.TokenDigestKey);

    public string CreateToken() => Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    public string Digest(string rawToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);
        return Convert.ToHexStringLower(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(rawToken)));
    }

    public bool Verify(string rawToken, string expectedDigest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedDigest);
        var actual = Digest(rawToken);
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(expectedDigest));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] DecodeKey(string value)
    {
        try
        {
            var key = Convert.FromBase64String(value);
            if (key.Length < 32)
            {
                throw new InvalidOperationException("Security:TokenDigestKey must contain at least 32 random bytes, Base64-encoded.");
            }

            return key;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("Security:TokenDigestKey is not valid Base64.", exception);
        }
    }

    private static string Base64UrlEncode(byte[] bytes) => Convert.ToBase64String(bytes)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}
