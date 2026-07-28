using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

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
