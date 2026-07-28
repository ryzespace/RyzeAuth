using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface ISessionLimitPolicy
{
    int MaximumActiveDevices { get; }
}
