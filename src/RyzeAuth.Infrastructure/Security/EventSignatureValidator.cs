using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Security;

public sealed class EventSignatureValidator(IOptions<SecurityOptions> options) : IEventSignatureValidator
{
    private readonly byte[] _key = Convert.FromBase64String(options.Value.KeycloakEventSigningKey);

    public bool IsValid(string payload, string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature))
        {
            return false;
        }

        try
        {
            var expected = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(payload));
            var received = Convert.FromHexString(signature);
            return CryptographicOperations.FixedTimeEquals(expected, received);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
