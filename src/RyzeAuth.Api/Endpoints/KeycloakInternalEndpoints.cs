using System.Text.Json;
using MediatR;
using RyzeAuth.Application;

namespace RyzeAuth.Api.Endpoints;

public static class KeycloakInternalEndpoints
{
    private const string SignatureHeader = "X-RyzeAuth-Signature";

    public static IEndpointRouteBuilder MapKeycloakInternalEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/internal/keycloak").WithTags("Keycloak Internal").AllowAnonymous();
        group.MapPost("/events", RecordEvent).Produces<RiskDecisionResponse>(StatusCodes.Status200OK);
        group.MapPost("/risk-assessments", AssessRisk).Produces<RiskDecisionResponse>(StatusCodes.Status200OK);
        return endpoints;
    }

    private static async Task<IResult> RecordEvent(
        HttpRequest request,
        IEventSignatureValidator signatures,
        ISender sender,
        CancellationToken cancellationToken)
    {
        var payload = await ReadVerifiedPayloadAsync(request, signatures, cancellationToken);
        if (payload is null)
        {
            return Results.Unauthorized();
        }

        var eventRequest = JsonSerializer.Deserialize<KeycloakEventRequest>(payload, SerializerOptions);
        if (eventRequest is null || !IsFresh(eventRequest.OccurredAt) || string.IsNullOrWhiteSpace(eventRequest.EventType) || string.IsNullOrWhiteSpace(eventRequest.SubjectId))
        {
            return Results.BadRequest();
        }

        var decision = await sender.Send(new KeycloakSecurityEventCommand(
            eventRequest.EventType,
            eventRequest.SubjectId,
            eventRequest.SessionId,
            eventRequest.DeviceId,
            eventRequest.IpAddress,
            eventRequest.UserAgent,
            eventRequest.OccurredAt), cancellationToken);
        return Results.Ok(ToResponse(decision));
    }

    private static async Task<IResult> AssessRisk(
        HttpRequest request,
        IEventSignatureValidator signatures,
        IAdaptiveRiskService risk,
        CancellationToken cancellationToken)
    {
        var payload = await ReadVerifiedPayloadAsync(request, signatures, cancellationToken);
        if (payload is null)
        {
            return Results.Unauthorized();
        }

        var riskRequest = JsonSerializer.Deserialize<KeycloakRiskRequest>(payload, SerializerOptions);
        if (riskRequest is null || !IsFresh(riskRequest.OccurredAt) || string.IsNullOrWhiteSpace(riskRequest.SubjectId))
        {
            return Results.BadRequest();
        }

        var decision = await risk.AssessAsync(new LoginRiskInput(
            riskRequest.SubjectId,
            riskRequest.IpAddress,
            riskRequest.UserAgent,
            riskRequest.DeviceId,
            riskRequest.OccurredAt), cancellationToken);
        return Results.Ok(ToResponse(decision));
    }

    private static async Task<string?> ReadVerifiedPayloadAsync(HttpRequest request, IEventSignatureValidator signatures, CancellationToken cancellationToken)
    {
        if (request.ContentLength is null or <= 0 or > 32_768)
        {
            return null;
        }

        using var reader = new StreamReader(request.Body);
        var payload = await reader.ReadToEndAsync(cancellationToken);
        return signatures.IsValid(payload, request.Headers[SignatureHeader].FirstOrDefault()) ? payload : null;
    }

    private static bool IsFresh(DateTimeOffset occurredAt) => Math.Abs((DateTimeOffset.UtcNow - occurredAt).TotalMinutes) <= 5;

    private static RiskDecisionResponse ToResponse(AdaptiveRiskDecision? decision) => decision is null
        ? new RiskDecisionResponse(0, false, false, [])
        : new RiskDecisionResponse(decision.Score, decision.RequireMfa, decision.Block, decision.Signals);

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public sealed record KeycloakEventRequest(
        string EventType,
        string SubjectId,
        string? SessionId,
        string? DeviceId,
        string? IpAddress,
        string? UserAgent,
        DateTimeOffset OccurredAt);

    public sealed record KeycloakRiskRequest(
        string SubjectId,
        string? IpAddress,
        string? UserAgent,
        string? DeviceId,
        DateTimeOffset OccurredAt);

    public sealed record RiskDecisionResponse(int Score, bool RequireMfa, bool Block, IReadOnlyList<string> Signals);
}
