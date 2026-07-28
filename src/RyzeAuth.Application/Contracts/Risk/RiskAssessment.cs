using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record RiskAssessment(int Score, bool RequireStepUpMfa, bool Block, IReadOnlyList<string> Signals);
