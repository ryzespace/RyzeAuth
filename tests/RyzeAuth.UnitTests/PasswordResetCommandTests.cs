using FluentAssertions;
using Moq;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.UnitTests;

public sealed class PasswordResetCommandTests
{
    [Fact]
    public async Task CompleteResetConsumesOpaqueTokenResetsKeycloakAndRevokesSessions()
    {
        var now = new DateTimeOffset(2026, 7, 24, 10, 0, 0, TimeSpan.Zero);
        var ticket = PasswordResetTicket.Issue("keycloak-subject", "member@example.test", "digest", now, now.AddMinutes(15), null);
        var tickets = new Mock<IPasswordResetTicketStore>();
        var tokens = new Mock<IOpaqueTokenService>();
        var policy = new Mock<IPasswordPolicy>();
        var keycloak = new Mock<IKeycloakAdminClient>();
        var audit = new Mock<IAuditTrail>();
        tickets.Setup(x => x.FindByDigestAsync("digest", It.IsAny<CancellationToken>())).ReturnsAsync(ticket);
        tickets.Setup(x => x.SaveChangesAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        tokens.Setup(x => x.Digest("opaque-token")).Returns("digest");
        tokens.Setup(x => x.Verify("opaque-token", "digest")).Returns(true);
        policy.Setup(x => x.ValidateAsync("correct horse battery staple", null, It.IsAny<CancellationToken>())).ReturnsAsync(PasswordPolicyResult.Success);
        keycloak.Setup(x => x.ResetPasswordAsync("keycloak-subject", "correct horse battery staple", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        keycloak.Setup(x => x.LogoutAllSessionsAsync("keycloak-subject", It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        audit.Setup(x => x.RecordAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var handler = new CompletePasswordResetCommandHandler(tickets.Object, tokens.Object, policy.Object, keycloak.Object, audit.Object, new FakeClock(now));
        await handler.Handle(new CompletePasswordResetCommand("opaque-token", "correct horse battery staple", null), default);

        ticket.IsUsable(now).Should().BeFalse();
        keycloak.Verify(x => x.ResetPasswordAsync("keycloak-subject", "correct horse battery staple", It.IsAny<CancellationToken>()), Times.Once);
        keycloak.Verify(x => x.LogoutAllSessionsAsync("keycloak-subject", It.IsAny<CancellationToken>()), Times.Once);
    }

    private sealed class FakeClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
