using RyzeAuth.Application;
using RyzeAuth.Domain;

namespace RyzeAuth.Infrastructure.Security;

public sealed class ContractGeoIpRiskProvider : IGeoIpRiskProvider
{
    public Task<GeoIpRiskInfo> LookupAsync(string? ipAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new GeoIpRiskInfo(null, null, null, null, false, false, false));
    }
}

public sealed class AdaptiveRiskService(
    IGeoIpRiskProvider geoIp,
    ILoginObservationRepository observations,
    IDeviceSessionRepository devices,
    IOpaqueTokenService tokens,
    IRiskEngine riskEngine) : IAdaptiveRiskService
{
    public async Task<AdaptiveRiskDecision> AssessAsync(LoginRiskInput input, CancellationToken cancellationToken)
    {
        var geo = await geoIp.LookupAsync(input.IpAddress, cancellationToken);
        var score = 0;
        var signals = new List<string>();
        var deviceHash = tokens.Digest(input.DeviceId ?? input.UserAgent ?? "unknown-device");
        var activeDevices = await devices.ListActiveForSubjectAsync(input.SubjectId, cancellationToken);
        if (!activeDevices.Any(device => device.DeviceIdHash == deviceHash))
        {
            score += 25;
            signals.Add("new_device");
        }

        if (geo.IsVpn)
        {
            score += 20;
            signals.Add("vpn");
        }

        if (geo.IsProxy)
        {
            score += 25;
            signals.Add("proxy");
        }

        if (geo.IsTor)
        {
            score += 45;
            signals.Add("tor");
        }

        var previous = await observations.GetLatestForSubjectAsync(input.SubjectId, cancellationToken);
        if (previous is not null)
        {
            if (!string.IsNullOrWhiteSpace(geo.CountryCode)
                && !string.IsNullOrWhiteSpace(previous.CountryCode)
                && !string.Equals(geo.CountryCode, previous.CountryCode, StringComparison.OrdinalIgnoreCase))
            {
                score += 20;
                signals.Add("new_country");
            }

            if (IsImpossibleTravel(previous, geo, input.OccurredAt))
            {
                score += 50;
                signals.Add("impossible_travel");
            }
        }

        var distributed = await riskEngine.AssessAsync(new RiskContext(input.SubjectId, input.IpAddress, input.UserAgent, geo.CountryCode), cancellationToken);
        score += distributed.Score;
        signals.AddRange(distributed.Signals);
        var requireMfa = score >= 50 || distributed.RequireStepUpMfa;
        return new AdaptiveRiskDecision(Math.Min(score, 100), requireMfa, distributed.Block || score >= 90, signals.Distinct(StringComparer.Ordinal).ToArray(), geo);
    }

    public async Task RecordSuccessfulLoginAsync(LoginRiskInput input, AdaptiveRiskDecision decision, CancellationToken cancellationToken)
    {
        var deviceHash = tokens.Digest(input.DeviceId ?? input.UserAgent ?? "unknown-device");
        var observation = LoginObservation.Create(
            input.SubjectId,
            tokens.Digest(input.IpAddress ?? "unknown-ip"),
            deviceHash,
            decision.Geo.CountryCode,
            decision.Geo.Latitude,
            decision.Geo.Longitude,
            decision.Geo.IsVpn,
            decision.Geo.IsProxy,
            decision.Geo.IsTor,
            decision.Geo.AutonomousSystem,
            decision.Score,
            decision.RequireMfa,
            input.OccurredAt);
        await observations.AddAsync(observation, cancellationToken);
        await observations.SaveChangesAsync(cancellationToken);
    }

    private static bool IsImpossibleTravel(LoginObservation previous, GeoIpRiskInfo current, DateTimeOffset occurredAt)
    {
        if (previous.Latitude is null || previous.Longitude is null || current.Latitude is null || current.Longitude is null)
        {
            return false;
        }

        var elapsed = occurredAt - previous.OccurredAt;
        if (elapsed <= TimeSpan.Zero || elapsed > TimeSpan.FromHours(24))
        {
            return false;
        }

        var distance = KilometersBetween(previous.Latitude.Value, previous.Longitude.Value, current.Latitude.Value, current.Longitude.Value);
        return distance / elapsed.TotalHours > 900;
    }

    private static double KilometersBetween(decimal latitudeA, decimal longitudeA, decimal latitudeB, decimal longitudeB)
    {
        const double radius = 6371;
        var latA = DegreesToRadians((double)latitudeA);
        var latB = DegreesToRadians((double)latitudeB);
        var latitudeDelta = DegreesToRadians((double)(latitudeB - latitudeA));
        var longitudeDelta = DegreesToRadians((double)(longitudeB - longitudeA));
        var haversine = Math.Sin(latitudeDelta / 2) * Math.Sin(latitudeDelta / 2)
            + Math.Cos(latA) * Math.Cos(latB) * Math.Sin(longitudeDelta / 2) * Math.Sin(longitudeDelta / 2);
        return radius * 2 * Math.Atan2(Math.Sqrt(haversine), Math.Sqrt(1 - haversine));
    }

    private static double DegreesToRadians(double degrees) => degrees * Math.PI / 180;
}
