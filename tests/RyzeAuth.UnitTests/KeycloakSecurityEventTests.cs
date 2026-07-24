using Moq;
using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.UnitTests;

public sealed class KeycloakSecurityEventTests
{
    [Fact]
    public async Task LoginEventRecordsRiskAndSendsVerifiedUserNotification()
    {
        var devices = new Mock<IDeviceSessionRepository>();
        var adaptiveRisk = new Mock<IAdaptiveRiskService>();
        var keycloak = new Mock<IKeycloakAdminClient>();
        var distributedRisk = new Mock<IRiskEngine>();
        var audit = new Mock<IAuditTrail>();
        var notifications = new Mock<ISecurityNotificationSender>();
        var tokens = new Mock<IOpaqueTokenService>();
        var limit = new Mock<ISessionLimitPolicy>();
        var now = new DateTimeOffset(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);
        var decision = new AdaptiveRiskDecision(25, false, false, ["new_device"], new GeoIpRiskInfo("PL", null, null, null, false, false, false));
        adaptiveRisk.Setup(x => x.AssessAsync(It.IsAny<LoginRiskInput>(), It.IsAny<CancellationToken>())).ReturnsAsync(decision);
        adaptiveRisk.Setup(x => x.RecordSuccessfulLoginAsync(It.IsAny<LoginRiskInput>(), decision, It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        keycloak.Setup(x => x.GetUserAsync("kc-user", It.IsAny<CancellationToken>())).ReturnsAsync(new KeycloakUser("kc-user", "member@example.test", true, true));
        audit.Setup(x => x.RecordAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        notifications.Setup(x => x.SendAsync(It.IsAny<SecurityNotification>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var handler = new KeycloakSecurityEventCommandHandler(
            devices.Object,
            adaptiveRisk.Object,
            keycloak.Object,
            distributedRisk.Object,
            audit.Object,
            notifications.Object,
            tokens.Object,
            limit.Object,
            new FixedClock(now));
        await handler.Handle(new KeycloakSecurityEventCommand("LOGIN", "kc-user", null, "device", "203.0.113.2", "browser", now), default);

        notifications.Verify(x => x.SendAsync(
            It.Is<SecurityNotification>(notification => notification.RecipientEmail == "member@example.test" && notification.EventType == "LOGIN"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }
}
