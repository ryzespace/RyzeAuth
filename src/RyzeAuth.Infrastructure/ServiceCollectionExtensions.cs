using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;
using RyzeAuth.Domain;
using RyzeAuth.Infrastructure.Keycloak;
using RyzeAuth.Infrastructure.Notifications;
using RyzeAuth.Infrastructure.Persistence;
using RyzeAuth.Infrastructure.Security;
using StackExchange.Redis;

namespace RyzeAuth.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddRyzeAuthInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<KeycloakOptions>().Bind(configuration.GetSection(KeycloakOptions.SectionName))
            .Validate(x => Uri.TryCreate(x.Authority, UriKind.Absolute, out _) && Uri.TryCreate(x.AdminBaseUrl, UriKind.Absolute, out _) &&
                !string.IsNullOrWhiteSpace(x.Realm) && !string.IsNullOrWhiteSpace(x.AdminClientId) && !string.IsNullOrWhiteSpace(x.AdminClientSecret),
                "Keycloak configuration is incomplete.").ValidateOnStart();
        services.AddOptions<SecurityOptions>().Bind(configuration.GetSection(SecurityOptions.SectionName))
            .Validate(x => SecurityOptions.IsValidTokenDigestKey(x.TokenDigestKey) && SecurityOptions.IsValidTokenDigestKey(x.KeycloakEventSigningKey) && Uri.TryCreate(x.PublicResetBaseUrl, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps,
                "Security configuration requires Base64 keys and an HTTPS reset URL.").ValidateOnStart();
        services.AddOptions<SmtpOptions>().Bind(configuration.GetSection(SmtpOptions.SectionName)).ValidateOnStart();

        var connectionString = configuration.GetConnectionString("RyzeAuth")
            ?? throw new InvalidOperationException("ConnectionStrings:RyzeAuth is required.");
        services.AddDbContext<RyzeAuthDbContext>(options => options.UseNpgsql(connectionString, npgsql =>
            npgsql.MigrationsAssembly(typeof(RyzeAuthDbContext).Assembly.FullName)));

        var redisConnection = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException("ConnectionStrings:Redis is required.");
        var redis = ConnectionMultiplexer.Connect(new ConfigurationOptions
        {
            EndPoints = { redisConnection },
            AbortOnConnectFail = false,
            ConnectRetry = 3,
            ConnectTimeout = 5_000
        });
        services.AddSingleton<IConnectionMultiplexer>(redis);
        services.AddDataProtection()
            .SetApplicationName("RyzeAuth")
            .PersistKeysToStackExchangeRedis(redis, "ryzeauth:dataprotection-keys");
        services.AddMemoryCache();
        services.AddHttpClient<IKeycloakAdminClient, KeycloakAdminClient>((provider, client) =>
        {
            var keycloak = provider.GetRequiredService<IOptions<KeycloakOptions>>().Value;
            client.BaseAddress = new Uri(keycloak.AdminBaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
            client.Timeout = TimeSpan.FromSeconds(10);
        });
        services.AddHttpClient<HttpsPasswordPolicy>(client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com/range/", UriKind.Absolute);
            client.Timeout = TimeSpan.FromSeconds(5);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("RyzeAuth-password-policy/1.0");
        });

        services.AddScoped<IApiKeyRepository, EfApiKeyRepository>();
        services.AddScoped<IOrganizationRepository, EfOrganizationRepository>();
        services.AddScoped<IPasswordResetTicketStore, EfPasswordResetTicketStore>();
        services.AddScoped<IDeviceSessionRepository, EfDeviceSessionRepository>();
        services.AddScoped<ILoginObservationRepository, EfLoginObservationRepository>();
        services.AddScoped<IAuditTrail, EfAuditTrail>();
        services.AddScoped<IAuditReadRepository, EfAuditReadRepository>();
        services.AddScoped<IOrganizationAuthorizer, EfOrganizationAuthorizer>();
        services.AddSingleton<IOpaqueTokenService, OpaqueTokenService>();
        services.AddSingleton<IEventSignatureValidator, EventSignatureValidator>();
        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<ISessionLimitPolicy, SessionLimitPolicy>();
        services.AddScoped<IPasswordPolicy, HttpsPasswordPolicy>();
        services.AddScoped<IResetNotificationSender, SmtpResetNotificationSender>();
        services.AddScoped<ISecurityNotificationSender, SmtpResetNotificationSender>();
        services.AddSingleton<IRiskEngine, RedisRiskEngine>();
        services.AddSingleton<IRequestRateLimiter, RedisRequestRateLimiter>();
        services.AddSingleton<ITokenBlacklistService, TokenBlacklistService>();
        services.AddSingleton<IGeoIpRiskProvider, ContractGeoIpRiskProvider>();
        services.AddScoped<IAdaptiveRiskService, AdaptiveRiskService>();
        return services;
    }
}
