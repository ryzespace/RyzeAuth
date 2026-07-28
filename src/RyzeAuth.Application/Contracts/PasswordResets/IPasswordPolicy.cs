using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IPasswordPolicy
{
    Task<PasswordPolicyResult> ValidateAsync(string password, string? userName, CancellationToken cancellationToken);
}
