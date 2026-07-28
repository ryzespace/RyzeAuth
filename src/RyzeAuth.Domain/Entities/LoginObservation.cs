namespace RyzeAuth.Domain;

public sealed class LoginObservation
{
    private LoginObservation() { }

    public Guid Id { get; private set; }
    public string SubjectId { get; private set; } = null!;
    public string IpHash { get; private set; } = null!;
    public string DeviceIdHash { get; private set; } = null!;
    public string? CountryCode { get; private set; }
    public decimal? Latitude { get; private set; }
    public decimal? Longitude { get; private set; }
    public bool IsVpn { get; private set; }
    public bool IsProxy { get; private set; }
    public bool IsTor { get; private set; }
    public string? Asn { get; private set; }
    public int RiskScore { get; private set; }
    public bool StepUpRequired { get; private set; }
    public DateTimeOffset OccurredAt { get; private set; }

    public static LoginObservation Create(
        string subjectId,
        string ipHash,
        string deviceIdHash,
        string? countryCode,
        decimal? latitude,
        decimal? longitude,
        bool isVpn,
        bool isProxy,
        bool isTor,
        string? asn,
        int riskScore,
        bool stepUpRequired,
        DateTimeOffset occurredAt) => new()
        {
            Id = Guid.NewGuid(),
            SubjectId = subjectId,
            IpHash = ipHash,
            DeviceIdHash = deviceIdHash,
            CountryCode = countryCode,
            Latitude = latitude,
            Longitude = longitude,
            IsVpn = isVpn,
            IsProxy = isProxy,
            IsTor = isTor,
            Asn = asn,
            RiskScore = riskScore,
            StepUpRequired = stepUpRequired,
            OccurredAt = occurredAt
        };
}
