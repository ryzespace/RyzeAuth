using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

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
