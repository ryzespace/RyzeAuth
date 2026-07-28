using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

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
