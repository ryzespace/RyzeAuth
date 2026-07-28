using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IEventSignatureValidator
{
    bool IsValid(string payload, string? signature);
}
