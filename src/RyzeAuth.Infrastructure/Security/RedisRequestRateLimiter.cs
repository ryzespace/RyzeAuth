using RyzeAuth.Application;
using StackExchange.Redis;

namespace RyzeAuth.Infrastructure.Security;

public sealed class RedisRequestRateLimiter(IConnectionMultiplexer redis, IOpaqueTokenService tokens) : IRequestRateLimiter
{
    private const string Script = "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); end; if count > tonumber(ARGV[2]) then return 0; end; return 1;";

    public async Task<bool> TryAcquireAsync(string category, string partition, int permitLimit, TimeSpan window, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = (RedisKey)("rate:" + category + ":" + tokens.Digest(partition));
        var result = await redis.GetDatabase().ScriptEvaluateAsync(
            Script,
            [key],
            [(long)window.TotalMilliseconds, permitLimit]);
        return (long)result == 1;
    }
}
