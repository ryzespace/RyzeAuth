using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record CreateOrganizationCommand(string Slug, string DisplayName, string OwnerSubjectId) : IRequest<OrganizationResult>;
public sealed record OrganizationResult(Guid Id, string Slug, string DisplayName);

public sealed class CreateOrganizationCommandValidator : AbstractValidator<CreateOrganizationCommand>
{
    public CreateOrganizationCommandValidator()
    {
        RuleFor(x => x.Slug).Matches("^[a-z0-9][a-z0-9-]{2,62}$");
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(120);
        RuleFor(x => x.OwnerSubjectId).NotEmpty().MaximumLength(100);
    }
}

public sealed class CreateOrganizationCommandHandler(
    IOrganizationRepository organizations,
    IClock clock) : IRequestHandler<CreateOrganizationCommand, OrganizationResult>
{
    public async Task<OrganizationResult> Handle(CreateOrganizationCommand request, CancellationToken cancellationToken)
    {
        var org = Organization.Create(request.Slug, request.DisplayName, clock.UtcNow);
        await organizations.AddAsync(org, cancellationToken);
        await organizations.AddMembershipAsync(
            Membership.Create(org.Id, request.OwnerSubjectId, "Owner", "{}", clock.UtcNow), cancellationToken);
        await organizations.SaveChangesAsync(cancellationToken);
        return new OrganizationResult(org.Id, org.Slug, org.DisplayName);
    }
}

public sealed record AddMemberCommand(Guid OrganizationId, string ActorSubjectId, string SubjectId, string Role, string AttributesJson) : IRequest;

public sealed class AddMemberCommandValidator : AbstractValidator<AddMemberCommand>
{
    public AddMemberCommandValidator()
    {
        RuleFor(x => x.OrganizationId).NotEmpty();
        RuleFor(x => x.ActorSubjectId).NotEmpty();
        RuleFor(x => x.SubjectId).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Role).Must(x => x is "Owner" or "OrgAdmin" or "SecurityAdmin" or "Member")
            .WithMessage("Role must be Owner, OrgAdmin, SecurityAdmin or Member.");
        RuleFor(x => x.AttributesJson).NotEmpty().MaximumLength(8_000);
    }
}

public sealed class AddMemberCommandHandler(
    IOrganizationRepository organizations,
    IOrganizationAuthorizer authorizer,
    IClock clock) : IRequestHandler<AddMemberCommand>
{
    public async Task Handle(AddMemberCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageMembers, cancellationToken);
        if (await organizations.GetAsync(request.OrganizationId, cancellationToken) is null)
        {
            throw new NotFoundException("Organization does not exist.");
        }

        if (await organizations.GetMembershipAsync(request.OrganizationId, request.SubjectId, cancellationToken) is not null)
        {
            throw new SecurityValidationException("User already belongs to this organization.");
        }

        await organizations.AddMembershipAsync(
            Membership.Create(request.OrganizationId, request.SubjectId, request.Role, request.AttributesJson, clock.UtcNow), cancellationToken);
        await organizations.SaveChangesAsync(cancellationToken);
    }
}

public sealed record CreateApiKeyCommand(
    Guid OrganizationId,
    string ActorSubjectId,
    string Name,
    IReadOnlyList<string> Scopes,
    DateTimeOffset? ExpiresAt) : IRequest<CreateApiKeyResult>;

public sealed record CreateApiKeyResult(Guid Id, string ApiKey, string Prefix, DateTimeOffset? ExpiresAt);

public sealed class CreateApiKeyCommandValidator : AbstractValidator<CreateApiKeyCommand>
{
    public CreateApiKeyCommandValidator()
    {
        RuleFor(x => x.OrganizationId).NotEmpty();
        RuleFor(x => x.ActorSubjectId).NotEmpty();
        RuleFor(x => x.Name).NotEmpty().MaximumLength(120);
        RuleFor(x => x.Scopes).NotEmpty().Must(scopes => scopes.All(scope =>
            System.Text.RegularExpressions.Regex.IsMatch(scope, "^[a-z][a-z0-9:_-]{1,80}$")))
            .WithMessage("Each scope must be a lowercase scope identifier.");
        RuleFor(x => x.ExpiresAt).Must(x => x is null || x > DateTimeOffset.UtcNow)
            .WithMessage("Expiration must be in the future.");
    }
}

public sealed class CreateApiKeyCommandHandler(
    IApiKeyRepository apiKeys,
    IOrganizationAuthorizer authorizer,
    IOpaqueTokenService tokens,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<CreateApiKeyCommand, CreateApiKeyResult>
{
    public async Task<CreateApiKeyResult> Handle(CreateApiKeyCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageApiKeys, cancellationToken);
        var now = clock.UtcNow;
        var entropy = tokens.CreateToken();
        var prefix = $"rza_{entropy[..12]}";
        var apiKey = $"{prefix}.{entropy}";
        var entity = ApiKey.Create(request.OrganizationId, request.Name, prefix, tokens.Digest(apiKey), request.Scopes,
            request.ActorSubjectId, now, request.ExpiresAt);

        await apiKeys.AddAsync(entity, cancellationToken);
        await apiKeys.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("api_key.created", "success", now,
            request.ActorSubjectId, request.OrganizationId, metadataJson: "{\"keyId\":\"" + entity.Id + "\"}"), cancellationToken);
        return new CreateApiKeyResult(entity.Id, apiKey, prefix, entity.ExpiresAt);
    }
}

public sealed record RevokeApiKeyCommand(Guid OrganizationId, Guid ApiKeyId, string ActorSubjectId) : IRequest;

public sealed class RevokeApiKeyCommandHandler(
    IApiKeyRepository apiKeys,
    IOrganizationAuthorizer authorizer,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<RevokeApiKeyCommand>
{
    public async Task Handle(RevokeApiKeyCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageApiKeys, cancellationToken);
        var key = await apiKeys.GetAsync(request.ApiKeyId, cancellationToken);
        if (key is null || key.OrganizationId != request.OrganizationId)
        {
            throw new NotFoundException("API key does not exist.");
        }

        key.Revoke(clock.UtcNow);
        await apiKeys.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("api_key.revoked", "success", clock.UtcNow,
            request.ActorSubjectId, request.OrganizationId, metadataJson: "{\"keyId\":\"" + key.Id + "\"}"), cancellationToken);
    }
}

public sealed record RequestPasswordResetCommand(string Email, string? RequestedIp, Uri PublicResetBaseUrl) : IRequest;

public sealed class RequestPasswordResetCommandValidator : AbstractValidator<RequestPasswordResetCommand>
{
    public RequestPasswordResetCommandValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(320);
        RuleFor(x => x.PublicResetBaseUrl).Must(url => url.Scheme == Uri.UriSchemeHttps)
            .WithMessage("Password-reset URLs must use HTTPS.");
    }
}

public sealed class RequestPasswordResetCommandHandler(
    IKeycloakAdminClient keycloak,
    IPasswordResetTicketStore tickets,
    IOpaqueTokenService tokens,
    IResetNotificationSender notifications,
    IAuditTrail auditTrail,
    IRiskEngine riskEngine,
    IClock clock) : IRequestHandler<RequestPasswordResetCommand>
{
    public async Task Handle(RequestPasswordResetCommand request, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindUserByEmailAsync(request.Email, cancellationToken);
        if (user is null || !user.Enabled)
        {
            await riskEngine.RegisterFailureAsync("password_reset_unknown", request.Email, request.RequestedIp, cancellationToken);
            return;
        }

        var risk = await riskEngine.AssessAsync(new RiskContext(user.SubjectId, request.RequestedIp, null, null), cancellationToken);
        if (risk.Block)
        {
            await auditTrail.RecordAsync(SecurityAuditEvent.Create("password_reset.requested", "blocked", clock.UtcNow, user.SubjectId), cancellationToken);
            return;
        }

        var now = clock.UtcNow;
        var token = tokens.CreateToken();
        await tickets.InvalidateActiveForSubjectAsync(user.SubjectId, now, cancellationToken);
        await tickets.AddAsync(PasswordResetTicket.Issue(user.SubjectId, user.Email, tokens.Digest(token), now,
            now.AddMinutes(15), request.RequestedIp is null ? null : tokens.Digest(request.RequestedIp)), cancellationToken);
        await tickets.SaveChangesAsync(cancellationToken);

        var resetUrl = new UriBuilder(request.PublicResetBaseUrl) { Query = $"token={Uri.EscapeDataString(token)}" }.Uri;
        await notifications.SendAsync(user.Email, resetUrl, now.AddMinutes(15), cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("password_reset.requested", "success", now, user.SubjectId), cancellationToken);
    }
}

public sealed record CompletePasswordResetCommand(string Token, string NewPassword, string? UserName) : IRequest;

public sealed class CompletePasswordResetCommandValidator : AbstractValidator<CompletePasswordResetCommand>
{
    public CompletePasswordResetCommandValidator()
    {
        RuleFor(x => x.Token).NotEmpty().MaximumLength(200);
        RuleFor(x => x.NewPassword).NotEmpty().MaximumLength(512);
    }
}

public sealed class CompletePasswordResetCommandHandler(
    IPasswordResetTicketStore tickets,
    IOpaqueTokenService tokens,
    IPasswordPolicy passwordPolicy,
    IKeycloakAdminClient keycloak,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<CompletePasswordResetCommand>
{
    public async Task Handle(CompletePasswordResetCommand request, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        var ticket = await tickets.FindByDigestAsync(tokens.Digest(request.Token), cancellationToken);
        if (ticket is null || !ticket.IsUsable(now) || !tokens.Verify(request.Token, ticket.TokenDigest))
        {
            throw new SecurityValidationException("Password-reset link is invalid or expired.");
        }

        var policy = await passwordPolicy.ValidateAsync(request.NewPassword, request.UserName, cancellationToken);
        if (!policy.IsValid)
        {
            throw new SecurityValidationException(string.Join(" ", policy.Errors));
        }

        await keycloak.ResetPasswordAsync(ticket.SubjectId, request.NewPassword, cancellationToken);
        await keycloak.LogoutAllSessionsAsync(ticket.SubjectId, cancellationToken);
        ticket.MarkUsed(now);
        await tickets.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("password_reset.completed", "success", now, ticket.SubjectId), cancellationToken);
    }
}

public sealed record IntrospectApiKeyQuery(string ApiKey, string? RequiredScope) : IRequest<ApiKeyIntrospectionResult>;
public sealed record ApiKeyIntrospectionResult(bool Active, Guid? OrganizationId, IReadOnlyList<string> Scopes, Guid? KeyId, string? Reason);

public sealed class IntrospectApiKeyQueryHandler(
    IApiKeyRepository apiKeys,
    IOpaqueTokenService tokens,
    IClock clock) : IRequestHandler<IntrospectApiKeyQuery, ApiKeyIntrospectionResult>
{
    public async Task<ApiKeyIntrospectionResult> Handle(IntrospectApiKeyQuery request, CancellationToken cancellationToken)
    {
        var separator = request.ApiKey.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return new(false, null, [], null, "malformed");
        }

        var prefix = request.ApiKey[..separator];
        var key = await apiKeys.FindByPrefixAsync(prefix, cancellationToken);
        if (key is null || !tokens.Verify(request.ApiKey, key.SecretDigest))
        {
            return new(false, null, [], null, "invalid");
        }

        if (!key.IsActive(clock.UtcNow))
        {
            return new(false, key.OrganizationId, [], key.Id, "expired_or_revoked");
        }

        if (!string.IsNullOrWhiteSpace(request.RequiredScope) && !key.Scopes.Contains(request.RequiredScope, StringComparer.Ordinal))
        {
            return new(false, key.OrganizationId, key.Scopes, key.Id, "missing_scope");
        }

        key.MarkUsed(clock.UtcNow);
        await apiKeys.SaveChangesAsync(cancellationToken);
        return new(true, key.OrganizationId, key.Scopes, key.Id, null);
    }
}

public sealed record RevokeAllMySessionsCommand(string SubjectId, string? TokenId, DateTimeOffset? TokenExpiresAt) : IRequest;

public sealed class RevokeAllMySessionsCommandHandler(
    IKeycloakAdminClient keycloak,
    ITokenBlacklistService blacklist,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<RevokeAllMySessionsCommand>
{
    public async Task Handle(RevokeAllMySessionsCommand request, CancellationToken cancellationToken)
    {
        var now = clock.UtcNow;
        await keycloak.LogoutAllSessionsAsync(request.SubjectId, cancellationToken);
        await blacklist.RevokeSubjectAsync(request.SubjectId, now, cancellationToken);
        if (!string.IsNullOrWhiteSpace(request.TokenId) && request.TokenExpiresAt is not null)
        {
            await blacklist.RevokeTokenAsync(request.TokenId, request.TokenExpiresAt.Value, cancellationToken);
        }

        await auditTrail.RecordAsync(SecurityAuditEvent.Create("sessions.revoked_all", "success", now, request.SubjectId), cancellationToken);
    }
}

public sealed record DeviceSessionResult(
    Guid Id,
    string? DisplayName,
    string UserAgent,
    string? CountryCode,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastSeenAt,
    bool IsTrusted);

public sealed record GetMyDevicesQuery(string SubjectId) : IRequest<IReadOnlyList<DeviceSessionResult>>;

public sealed class GetMyDevicesQueryHandler(IDeviceSessionRepository devices) : IRequestHandler<GetMyDevicesQuery, IReadOnlyList<DeviceSessionResult>>
{
    public async Task<IReadOnlyList<DeviceSessionResult>> Handle(GetMyDevicesQuery request, CancellationToken cancellationToken)
    {
        var sessions = await devices.ListActiveForSubjectAsync(request.SubjectId, cancellationToken);
        return sessions.Select(session => new DeviceSessionResult(
            session.Id,
            session.DisplayName,
            session.UserAgent,
            session.CountryCode,
            session.CreatedAt,
            session.LastSeenAt,
            session.IsTrusted)).ToArray();
    }
}

public sealed record UpdateDeviceCommand(string SubjectId, Guid DeviceId, string? DisplayName, bool? IsTrusted) : IRequest;

public sealed class UpdateDeviceCommandValidator : AbstractValidator<UpdateDeviceCommand>
{
    public UpdateDeviceCommandValidator()
    {
        RuleFor(x => x.SubjectId).NotEmpty();
        RuleFor(x => x.DeviceId).NotEmpty();
        RuleFor(x => x.DisplayName).MaximumLength(120).When(x => x.DisplayName is not null);
        RuleFor(x => x).Must(x => x.DisplayName is not null || x.IsTrusted is not null)
            .WithMessage("At least one device property must be supplied.");
    }
}

public sealed class UpdateDeviceCommandHandler(IDeviceSessionRepository devices) : IRequestHandler<UpdateDeviceCommand>
{
    public async Task Handle(UpdateDeviceCommand request, CancellationToken cancellationToken)
    {
        var device = await devices.GetAsync(request.DeviceId, cancellationToken);
        if (device is null || device.SubjectId != request.SubjectId || device.RevokedAt is not null)
        {
            throw new NotFoundException("Device session does not exist.");
        }

        if (request.DisplayName is not null)
        {
            device.Rename(request.DisplayName);
        }

        if (request.IsTrusted is not null)
        {
            device.SetTrusted(request.IsTrusted.Value);
        }

        await devices.SaveChangesAsync(cancellationToken);
    }
}

public sealed record RevokeDeviceCommand(string SubjectId, Guid DeviceId) : IRequest;

public sealed class RevokeDeviceCommandHandler(
    IDeviceSessionRepository devices,
    IKeycloakAdminClient keycloak,
    IAuditTrail auditTrail,
    IClock clock) : IRequestHandler<RevokeDeviceCommand>
{
    public async Task Handle(RevokeDeviceCommand request, CancellationToken cancellationToken)
    {
        var device = await devices.GetAsync(request.DeviceId, cancellationToken);
        if (device is null || device.SubjectId != request.SubjectId || device.RevokedAt is not null)
        {
            throw new NotFoundException("Device session does not exist.");
        }

        await keycloak.LogoutSessionAsync(device.KeycloakSessionId, cancellationToken);
        device.Revoke(clock.UtcNow);
        await devices.SaveChangesAsync(cancellationToken);
        await auditTrail.RecordAsync(SecurityAuditEvent.Create("device.revoked", "success", clock.UtcNow, request.SubjectId), cancellationToken);
    }
}

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

public sealed record SecurityAuditResult(
    Guid Id,
    DateTimeOffset OccurredAt,
    string EventType,
    string Outcome,
    Guid? OrganizationId,
    string MetadataJson);

public sealed record GetMySecurityAuditQuery(string SubjectId, int Take) : IRequest<IReadOnlyList<SecurityAuditResult>>;

public sealed class GetMySecurityAuditQueryHandler(IAuditReadRepository audit) : IRequestHandler<GetMySecurityAuditQuery, IReadOnlyList<SecurityAuditResult>>
{
    public async Task<IReadOnlyList<SecurityAuditResult>> Handle(GetMySecurityAuditQuery request, CancellationToken cancellationToken)
    {
        var events = await audit.ListForSubjectAsync(request.SubjectId, Math.Clamp(request.Take, 1, 100), cancellationToken);
        return events.Select(MapAudit).ToArray();
    }

    internal static SecurityAuditResult MapAudit(SecurityAuditEvent item) => new(item.Id, item.OccurredAt, item.EventType, item.Outcome, item.OrganizationId, item.MetadataJson);
}

public sealed record GetOrganizationSecurityAuditQuery(Guid OrganizationId, string ActorSubjectId, int Take) : IRequest<IReadOnlyList<SecurityAuditResult>>;

public sealed class GetOrganizationSecurityAuditQueryHandler(
    IAuditReadRepository audit,
    IOrganizationAuthorizer authorizer) : IRequestHandler<GetOrganizationSecurityAuditQuery, IReadOnlyList<SecurityAuditResult>>
{
    public async Task<IReadOnlyList<SecurityAuditResult>> Handle(GetOrganizationSecurityAuditQuery request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ViewAudit, cancellationToken);
        var events = await audit.ListForOrganizationAsync(request.OrganizationId, Math.Clamp(request.Take, 1, 100), cancellationToken);
        return events.Select(GetMySecurityAuditQueryHandler.MapAudit).ToArray();
    }
}
