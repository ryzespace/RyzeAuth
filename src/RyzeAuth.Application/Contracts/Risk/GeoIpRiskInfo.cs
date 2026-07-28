using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record GeoIpRiskInfo(
    string? CountryCode,
    decimal? Latitude,
    decimal? Longitude,
    string? AutonomousSystem,
    bool IsVpn,
    bool IsProxy,
    bool IsTor);
