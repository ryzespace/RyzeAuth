using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IGeoIpRiskProvider
{
    Task<GeoIpRiskInfo> LookupAsync(string? ipAddress, CancellationToken cancellationToken);
}
