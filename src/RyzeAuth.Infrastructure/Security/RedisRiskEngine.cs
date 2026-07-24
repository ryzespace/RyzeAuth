using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Security;

public sealed class RedisRiskEngine(
    IConnectionMultiplexer redis,
    IOpaqueTokenService tokens,
    ILogger<RedisRiskEngine> logger) : IRiskEngine
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    private static readonly Action<ILogger, string, Exception?> LogSecurityFailure = LoggerMessage.Define<string>(
        LogLevel.Information, new EventId(1001, "SecurityFailure"), "Registered security failure of type {Kind}");

    public async Task<RiskAssessment> AssessAsync(RiskContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var db = redis.GetDatabase();
        var subjectCount = await db.StringGetAsync($"risk:fail:subject:{tokens.Digest(context.SubjectOrEmail)}");
        var ipCount = string.IsNullOrWhiteSpace(context.IpAddress)
            ? RedisValue.Null
            : await db.StringGetAsync($"risk:fail:ip:{tokens.Digest(context.IpAddress)}");
        var subjectFailures = (int)(subjectCount.HasValue ? (long)subjectCount : 0L);
        var ipFailures = (int)(ipCount.HasValue ? (long)ipCount : 0L);
        var signals = new List<string>();
        var score = 0;
        if (subjectFailures >= 5) { score += 50; signals.Add("many_attempts_for_account"); }
        if (ipFailures >= 20) { score += 40; signals.Add("many_attempts_from_ip"); }
        if (!string.IsNullOrWhiteSpace(context.CountryCode)) { signals.Add("geo_observed"); }
        return new RiskAssessment(score, RequireStepUpMfa: score >= 50, Block: subjectFailures >= 10 || ipFailures >= 50, signals);
    }

    public async Task RegisterFailureAsync(string kind, string principal, string? ipAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var db = redis.GetDatabase();
        await IncrementAsync(db, $"risk:{kind}:subject:{tokens.Digest(principal)}");
        if (!string.IsNullOrWhiteSpace(ipAddress))
        {
            await IncrementAsync(db, $"risk:{kind}:ip:{tokens.Digest(ipAddress)}");
        }
        LogSecurityFailure(logger, kind, null);
    }

    private static async Task IncrementAsync(IDatabase db, RedisKey key)
    {
        _ = await db.StringIncrementAsync(key);
        _ = await db.KeyExpireAsync(key, Window);
    }
}
