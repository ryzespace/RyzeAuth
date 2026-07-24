using FluentAssertions;
using Moq;
using RyzeAuth.Application;
using RyzeAuth.Domain;
using RyzeAuth.Infrastructure.Security;

namespace RyzeAuth.UnitTests;

public sealed class AdaptiveRiskServiceTests
{
    [Fact]
    public async Task AssessAsyncRequiresMfaForImpossibleTravelAndNewDevice()
    {
        var geo = new Mock<IGeoIpRiskProvider>();
        var observations = new Mock<ILoginObservationRepository>();
        var devices = new Mock<IDeviceSessionRepository>();
        var tokens = new Mock<IOpaqueTokenService>();
        var distributedRisk = new Mock<IRiskEngine>();
        var now = new DateTimeOffset(2026, 7, 24, 12, 0, 0, TimeSpan.Zero);
        geo.Setup(x => x.LookupAsync("203.0.113.15", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GeoIpRiskInfo("PL", 50.0647m, 19.9450m, "AS123", false, false, false));
        observations.Setup(x => x.GetLatestForSubjectAsync("kc-user", It.IsAny<CancellationToken>()))
            .ReturnsAsync(LoginObservation.Create("kc-user", "ip", "device", "US", 40.7128m, -74.0060m, false, false, false, "AS456", 0, false, now.AddHours(-1)));
        devices.Setup(x => x.ListActiveForSubjectAsync("kc-user", It.IsAny<CancellationToken>()))
            .ReturnsAsync([]);
        tokens.Setup(x => x.Digest(It.IsAny<string>())).Returns((string value) => "digest-" + value);
        distributedRisk.Setup(x => x.AssessAsync(It.IsAny<RiskContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RiskAssessment(0, false, false, []));

        var service = new AdaptiveRiskService(geo.Object, observations.Object, devices.Object, tokens.Object, distributedRisk.Object);
        var decision = await service.AssessAsync(new LoginRiskInput("kc-user", "203.0.113.15", "browser", "new-device", now), default);

        decision.RequireMfa.Should().BeTrue();
        decision.Block.Should().BeTrue();
        decision.Signals.Should().Contain(["new_device", "new_country", "impossible_travel"]);
        decision.Score.Should().BeGreaterOrEqualTo(95);
    }
}
