using FluentAssertions;
using Microsoft.Extensions.Options;
using RyzeAuth.Infrastructure;
using RyzeAuth.Infrastructure.Security;

namespace RyzeAuth.UnitTests;

public sealed class OpaqueTokenServiceTests
{
    [Fact]
    public void CreateTokenCreatesUrlSafe256BitTokenAndVerifiesDigest()
    {
        var sut = new OpaqueTokenService(Options.Create(new SecurityOptions
        {
            TokenDigestKey = Convert.ToBase64String(new byte[32]),
            KeycloakEventSigningKey = Convert.ToBase64String(new byte[32]),
            PublicResetBaseUrl = "https://auth.example.test/reset"
        }));

        var token = sut.CreateToken();
        var digest = sut.Digest(token);

        token.Should().HaveLength(43);
        token.Should().NotContainAny("+", "/", "=");
        digest.Should().HaveLength(64);
        sut.Verify(token, digest).Should().BeTrue();
        sut.Verify(token + "x", digest).Should().BeFalse();
    }
}
