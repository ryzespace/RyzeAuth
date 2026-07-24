using System.Threading.RateLimiting;
using FluentValidation;
using Microsoft.EntityFrameworkCore;
using MediatR;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using RyzeAuth.Api.Endpoints;
using RyzeAuth.Api.Grpc;
using RyzeAuth.Api.Middleware;
using RyzeAuth.Application;
using RyzeAuth.Infrastructure;
using RyzeAuth.Infrastructure.Persistence;
using Scalar.AspNetCore;
using Serilog;
using Serilog.Context;
using Serilog.Enrichers.Span;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(new Serilog.Formatting.Compact.RenderedCompactJsonFormatter())
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithSpan()
        .WriteTo.Console(new Serilog.Formatting.Compact.RenderedCompactJsonFormatter()));

    var keycloakAuthority = builder.Configuration["Keycloak:Authority"]
        ?? throw new InvalidOperationException("Keycloak:Authority is required.");
    var validAudience = builder.Configuration["Keycloak:ValidAudience"] ?? "ryzeauth-api";
    var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];

    builder.Services.AddRyzeAuthInfrastructure(builder.Configuration);
    builder.Services.AddValidatorsFromAssemblyContaining<CreateOrganizationCommandValidator>();
    builder.Services.AddMediatR(configuration =>
    {
        configuration.RegisterServicesFromAssemblyContaining<CreateOrganizationCommand>();
        configuration.AddOpenBehavior(typeof(ValidationBehavior<,>));
    });
    builder.Services.AddOpenApi();
    builder.Services.AddGrpc();
    builder.Services.AddHealthChecks().AddDbContextCheck<RyzeAuthDbContext>();
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.Authority = keycloakAuthority;
            options.Audience = validAudience;
            options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = keycloakAuthority,
                ValidateAudience = true,
                ValidAudience = validAudience,
                ValidateLifetime = true,
                NameClaimType = "preferred_username",
                RoleClaimType = "roles"
            };
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    var subject = context.Principal?.FindFirst("sub")?.Value;
                    var tokenId = context.Principal?.FindFirst("jti")?.Value;
                    var issuedAtValue = context.Principal?.FindFirst("iat")?.Value;
                    if (string.IsNullOrWhiteSpace(subject)
                        || !long.TryParse(issuedAtValue, out var issuedAt))
                    {
                        context.Fail("Token does not contain required subject and issued-at claims.");
                        return;
                    }

                    var blacklist = context.HttpContext.RequestServices.GetRequiredService<ITokenBlacklistService>();
                    if ((!string.IsNullOrWhiteSpace(tokenId) && await blacklist.IsTokenRevokedAsync(tokenId, context.HttpContext.RequestAborted))
                        || await blacklist.IsSubjectRevokedAsync(subject, DateTimeOffset.FromUnixTimeSeconds(issuedAt), context.HttpContext.RequestAborted))
                    {
                        context.Fail("Token has been revoked.");
                    }
                }
            };
        });
    builder.Services.AddAuthorization(options =>
    {
        options.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        options.AddPolicy("InternalService", policy => policy
            .RequireAuthenticatedUser()
            .RequireClaim("azp", "ryzeauth-internal"));
        options.AddPolicy("ScimRead", policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => HasScope(context.User, "scim:users:read") || HasScope(context.User, "scim:users:write")));
        options.AddPolicy("ScimWrite", policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => HasScope(context.User, "scim:users:write")));
        options.AddPolicy("RecentAuthentication", policy => policy
            .RequireAuthenticatedUser()
            .RequireAssertion(context => HasRecentAuthentication(context.User)));
    });
    builder.Services.AddCors(options => options.AddPolicy("strict", policy =>
    {
        if (allowedOrigins.Length != 0)
        {
            policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod();
        }
    }));
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.AddPolicy("password-reset", context => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(15),
                QueueLimit = 0,
                AutoReplenishment = true
            }));
    });
    builder.Services.AddOpenTelemetry()
        .WithTracing(tracing => tracing
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddOtlpExporter())
        .WithMetrics(metrics => metrics
            .AddAspNetCoreInstrumentation()
            .AddPrometheusExporter());

    var app = builder.Build();
    if (app.Configuration.GetValue<bool>("Database:ApplyMigrationsOnStartup"))
    {
        using var migrationScope = app.Services.CreateScope();
        await migrationScope.ServiceProvider.GetRequiredService<RyzeAuthDbContext>().Database.MigrateAsync();
    }

    app.UseExceptionHandler(errors => errors.Run(async context =>
    {
        var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        var (status, title, detail) = exception switch
        {
            ValidationException validation => (StatusCodes.Status400BadRequest, "Validation failed", string.Join(" ", validation.Errors.Select(error => error.ErrorMessage))),
            SecurityValidationException security => (StatusCodes.Status400BadRequest, "Security validation failed", security.Message),
            AuthorizationDeniedException => (StatusCodes.Status403Forbidden, "Forbidden", "You are not allowed to perform this operation."),
            NotFoundException => (StatusCodes.Status404NotFound, "Not found", "The requested resource does not exist."),
            UnauthorizedAccessException => (StatusCodes.Status401Unauthorized, "Unauthorized", "A valid token is required."),
            _ => (StatusCodes.Status500InternalServerError, "Internal server error", "An unexpected error occurred.")
        };
        context.Response.StatusCode = status;
        await Results.Problem(detail, statusCode: status, title: title).ExecuteAsync(context);
    }));
    app.Use(async (context, next) =>
    {
        var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId) || correlationId.Length > 128)
        {
            correlationId = context.TraceIdentifier;
        }

        context.Response.Headers["X-Correlation-ID"] = correlationId;
        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next();
        }
    });
    app.UseMiddleware<SecurityHeadersMiddleware>();
    if (!app.Environment.IsDevelopment())
    {
        app.UseHttpsRedirection();
    }

    app.UseSerilogRequestLogging();
    app.UseRateLimiter();
    app.UseCors("strict");
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapOpenApi().AllowAnonymous();
    app.MapScalarApiReference(options => options.WithTitle("RyzeAuth API")).AllowAnonymous();
    app.MapHealthChecks("/health/live").AllowAnonymous();
    app.MapHealthChecks("/health/ready").AllowAnonymous();
    app.MapPrometheusScrapingEndpoint("/metrics").AllowAnonymous();
    app.MapRyzeAuthEndpoints();
    app.MapKeycloakInternalEndpoints();
    app.MapScimEndpoints();
    app.MapTokenIntrospectionEndpoints();
    app.MapGrpcService<ApiKeyIntrospectionGrpcService>().RequireAuthorization("InternalService");

    await app.RunAsync();
}
catch (Exception exception)
{
    Log.Fatal(exception, "RyzeAuth terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

static bool HasScope(System.Security.Claims.ClaimsPrincipal user, string scope) => user.FindAll("scope")
    .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    .Contains(scope, StringComparer.Ordinal);

static bool HasRecentAuthentication(System.Security.Claims.ClaimsPrincipal user) => long.TryParse(user.FindFirst("auth_time")?.Value, out var authTime)
    && DateTimeOffset.UtcNow - DateTimeOffset.FromUnixTimeSeconds(authTime) <= TimeSpan.FromMinutes(5);

public partial class Program;
