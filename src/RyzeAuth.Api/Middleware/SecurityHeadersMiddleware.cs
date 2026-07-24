namespace RyzeAuth.Api.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next, IHostEnvironment environment)
{
    public async Task Invoke(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()";
        if (!environment.IsDevelopment())
        {
            headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload";
        }

        await next(context);
    }
}
