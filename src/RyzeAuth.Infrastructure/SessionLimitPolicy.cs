using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure;

public sealed class SessionLimitPolicy(IOptions<SecurityOptions> options) : ISessionLimitPolicy
{
    public int MaximumActiveDevices => options.Value.MaximumDevicesPerUser;
}
