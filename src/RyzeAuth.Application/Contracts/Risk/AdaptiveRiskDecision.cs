using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record AdaptiveRiskDecision(int Score, bool RequireMfa, bool Block, IReadOnlyList<string> Signals, GeoIpRiskInfo Geo);
