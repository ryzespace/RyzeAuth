using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

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
