using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record KeycloakSecurityEventCommand(
    string EventType,
    string SubjectId,
    string? SessionId,
    string? DeviceId,
    string? IpAddress,
    string? UserAgent,
    DateTimeOffset OccurredAt) : IRequest<AdaptiveRiskDecision?>;

public sealed class KeycloakSecurityEventCommandHandler(
    IDeviceSessionRepository devices,
    IAdaptiveRiskService adaptiveRisk,
    IKeycloakAdminClient keycloak,
    IRiskEngine riskEngine,
    IAuditTrail auditTrail,
    ISecurityNotificationSender notifications,
    IOpaqueTokenService tokens,
    ISessionLimitPolicy sessionLimit,
    IClock clock) : IRequestHandler<KeycloakSecurityEventCommand, AdaptiveRiskDecision?>
{
    public async Task<AdaptiveRiskDecision?> Handle(KeycloakSecurityEventCommand request, CancellationToken cancellationToken)
    {
        var eventType = request.EventType.Trim().ToUpperInvariant();
        if (eventType == "LOGIN_ERROR")
        {
            await riskEngine.RegisterFailureAsync("login", request.SubjectId, request.IpAddress, cancellationToken);
            await auditTrail.RecordAsync(SecurityAuditEvent.Create("login.failed", "failure", clock.UtcNow, request.SubjectId), cancellationToken);
            return null;
        }

        if (eventType == "LOGOUT" && !string.IsNullOrWhiteSpace(request.SessionId))
        {
            var session = await devices.FindByKeycloakSessionIdAsync(request.SessionId, cancellationToken);
            if (session is not null)
            {
                session.Revoke(clock.UtcNow);
                await devices.SaveChangesAsync(cancellationToken);
            }

            await auditTrail.RecordAsync(SecurityAuditEvent.Create("logout", "success", clock.UtcNow, request.SubjectId), cancellationToken);
            return null;
        }

        if (eventType != "LOGIN")
        {
            await auditTrail.RecordAsync(SecurityAuditEvent.Create("keycloak." + eventType.ToLowerInvariant(), "success", clock.UtcNow, request.SubjectId), cancellationToken);
            await NotifyAsync(eventType, request.SubjectId, request.OccurredAt, request.UserAgent, null, cancellationToken);
            return null;
        }

        var input = new LoginRiskInput(request.SubjectId, request.IpAddress, request.UserAgent, request.DeviceId, request.OccurredAt);
        var decision = await adaptiveRisk.AssessAsync(input, cancellationToken);
        await adaptiveRisk.RecordSuccessfulLoginAsync(input, decision, cancellationToken);
        if (!string.IsNullOrWhiteSpace(request.SessionId))
        {
            var session = await devices.FindByKeycloakSessionIdAsync(request.SessionId, cancellationToken);
            if (session is null)
            {
                var active = await devices.ListActiveForSubjectAsync(request.SubjectId, cancellationToken);
                if (active.Count >= sessionLimit.MaximumActiveDevices)
                {
                    var oldest = active.OrderBy(device => device.LastSeenAt).First();
                    await keycloak.LogoutSessionAsync(oldest.KeycloakSessionId, cancellationToken);
                    oldest.Revoke(clock.UtcNow);
                }

                await devices.AddAsync(DeviceSession.Create(
                    request.SubjectId,
                    request.SessionId,
                    tokens.Digest(request.DeviceId ?? request.UserAgent ?? "unknown-device"),
                    tokens.Digest(request.IpAddress ?? "unknown-ip"),
                    request.UserAgent ?? "unknown",
                    decision.Geo.CountryCode,
                    request.OccurredAt), cancellationToken);
            }
            else
            {
                session.Touch(request.OccurredAt);
            }

            await devices.SaveChangesAsync(cancellationToken);
        }

        await auditTrail.RecordAsync(SecurityAuditEvent.Create(
            "login",
            decision.Block ? "blocked" : "success",
            clock.UtcNow,
            request.SubjectId,
            metadataJson: "{\"riskScore\":" + decision.Score + ",\"stepUpRequired\":" + decision.RequireMfa.ToString().ToLowerInvariant() + "}"), cancellationToken);
        await NotifyAsync("LOGIN", request.SubjectId, request.OccurredAt, request.UserAgent, decision.Geo.CountryCode, cancellationToken);
        return decision;
    }

    private async Task NotifyAsync(string eventType, string subjectId, DateTimeOffset occurredAt, string? userAgent, string? countryCode, CancellationToken cancellationToken)
    {
        if (eventType is not "LOGIN" and not "UPDATE_PASSWORD" and not "UPDATE_EMAIL" and not "UPDATE_TOTP" and not "REMOVE_TOTP")
        {
            return;
        }

        var user = await keycloak.GetUserAsync(subjectId, cancellationToken);
        if (user is not null && user.Enabled && user.EmailVerified)
        {
            await notifications.SendAsync(new SecurityNotification(user.Email, eventType, occurredAt, userAgent, countryCode), cancellationToken);
        }
    }
}
