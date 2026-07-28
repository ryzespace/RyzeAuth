using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface ITokenBlacklistService
{
    Task RevokeTokenAsync(string tokenId, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    Task RevokeSubjectAsync(string subjectId, DateTimeOffset revokeAfter, CancellationToken cancellationToken);
    Task<bool> IsTokenRevokedAsync(string tokenId, CancellationToken cancellationToken);
    Task<bool> IsSubjectRevokedAsync(string subjectId, DateTimeOffset issuedAt, CancellationToken cancellationToken);
}
