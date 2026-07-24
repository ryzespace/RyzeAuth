using FluentAssertions;
using Moq;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.UnitTests;

public sealed class ApiKeyCommandTests
{
    [Fact]
    public async Task CreateApiKeyReturnsSecretOnceButPersistsOnlyDigest()
    {
        var organizationId = Guid.NewGuid();
        var clock = new FakeClock(new DateTimeOffset(2026, 7, 24, 10, 0, 0, TimeSpan.Zero));
        var keys = new Mock<IApiKeyRepository>();
        var authorization = new Mock<IOrganizationAuthorizer>();
        var token = new Mock<IOpaqueTokenService>();
        var audit = new Mock<IAuditTrail>();
        ApiKey? persisted = null;
        token.Setup(x => x.CreateToken()).Returns("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789_");
        token.Setup(x => x.Digest(It.IsAny<string>())).Returns((string raw) => "hmac:" + raw);
        keys.Setup(x => x.AddAsync(It.IsAny<ApiKey>(), It.IsAny<CancellationToken>()))
            .Callback<ApiKey, CancellationToken>((key, _) => persisted = key)
            .Returns(Task.CompletedTask);
        keys.Setup(x => x.SaveChangesAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        audit.Setup(x => x.RecordAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var handler = new CreateApiKeyCommandHandler(keys.Object, authorization.Object, token.Object, audit.Object, clock);
        var result = await handler.Handle(new CreateApiKeyCommand(organizationId, "kc-subject", "CI deploy", ["billing:read", "billing:write"], null), default);

        result.ApiKey.Should().StartWith("rza_abcdefghijkl.");
        persisted.Should().NotBeNull();
        persisted!.SecretDigest.Should().NotBe(result.ApiKey);
        persisted.SecretDigest.Should().Be("hmac:" + result.ApiKey);
        persisted.Scopes.Should().BeEquivalentTo(["billing:read", "billing:write"]);
        authorization.Verify(x => x.DemandAsync("kc-subject", organizationId, OrganizationAccess.ManageApiKeys, It.IsAny<CancellationToken>()), Times.Once);
        audit.Verify(x => x.RecordAsync(It.Is<SecurityAuditEvent>(a => a.EventType == "api_key.created"), It.IsAny<CancellationToken>()), Times.Once);
    }

    private sealed class FakeClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
