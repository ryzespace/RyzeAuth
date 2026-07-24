using System.Globalization;
using RyzeAuth.Application;
using RyzeAuth.Domain;
using StackExchange.Redis;

namespace RyzeAuth.Infrastructure.Security;

public sealed class TokenBlacklistService(
    IConnectionMultiplexer redis,
    IOpaqueTokenService tokens,
    IClock clock) : ITokenBlacklistService
{
    public async Task RevokeTokenAsync(string tokenId, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var ttl = expiresAt - clock.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            return;
        }

        await redis.GetDatabase().StringSetAsync(TokenKey(tokenId), "1", ttl);
    }

    public async Task RevokeSubjectAsync(string subjectId, DateTimeOffset revokeAfter, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await redis.GetDatabase().StringSetAsync(
            SubjectKey(subjectId),
            revokeAfter.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            TimeSpan.FromMinutes(20));
    }

    public async Task<bool> IsTokenRevokedAsync(string tokenId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await redis.GetDatabase().KeyExistsAsync(TokenKey(tokenId));
    }

    public async Task<bool> IsSubjectRevokedAsync(string subjectId, DateTimeOffset issuedAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var value = await redis.GetDatabase().StringGetAsync(SubjectKey(subjectId));
        return value.HasValue
            && long.TryParse(value.ToString(), CultureInfo.InvariantCulture, out var revokeAfter)
            && issuedAt.ToUnixTimeSeconds() <= revokeAfter;
    }

    private RedisKey TokenKey(string tokenId) => "token:blacklist:" + tokens.Digest(tokenId);
    private RedisKey SubjectKey(string subjectId) => "token:subject-revoked:" + tokens.Digest(subjectId);
}
