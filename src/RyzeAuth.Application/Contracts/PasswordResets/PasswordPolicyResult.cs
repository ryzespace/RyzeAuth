using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record PasswordPolicyResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static PasswordPolicyResult Success { get; } = new(true, []);
}
