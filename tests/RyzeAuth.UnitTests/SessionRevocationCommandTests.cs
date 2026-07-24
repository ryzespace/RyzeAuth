using Moq;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.UnitTests;

public sealed class SessionRevocationCommandTests
{
    [Fact]
    public async Task RevokeAllSessionsRevokesKeycloakSessionSubjectAndCurrentToken()
    {
        var keycloak = new Mock<IKeycloakAdminClient>();
        var blacklist = new Mock<ITokenBlacklistService>();
        var audit = new Mock<IAuditTrail>();
        var now = new DateTimeOffset(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);
        keycloak.Setup(x => x.LogoutAllSessionsAsync("kc-user", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        blacklist.Setup(x => x.RevokeSubjectAsync("kc-user", now, It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        blacklist.Setup(x => x.RevokeTokenAsync("jti", now.AddMinutes(10), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        audit.Setup(x => x.RecordAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var handler = new RevokeAllMySessionsCommandHandler(keycloak.Object, blacklist.Object, audit.Object, new FixedClock(now));
        await handler.Handle(new RevokeAllMySessionsCommand("kc-user", "jti", now.AddMinutes(10)), default);

        keycloak.Verify(x => x.LogoutAllSessionsAsync("kc-user", It.IsAny<CancellationToken>()), Times.Once);
        blacklist.Verify(x => x.RevokeSubjectAsync("kc-user", now, It.IsAny<CancellationToken>()), Times.Once);
        blacklist.Verify(x => x.RevokeTokenAsync("jti", now.AddMinutes(10), It.IsAny<CancellationToken>()), Times.Once);
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
