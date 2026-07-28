using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

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
