using FluentAssertions;
using Microsoft.Playwright;

namespace RyzeAuth.E2ETests;

public sealed class KeycloakLoginJourneyTests : IAsyncLifetime
{
    private IPlaywright _playwright = null!;
    private IBrowser _browser = null!;

    public async Task InitializeAsync()
    {
        _playwright = await Playwright.CreateAsync();
        _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
    }

    public async Task DisposeAsync()
    {
        await _browser.DisposeAsync();
        _playwright.Dispose();
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task AuthorizationCodeFlowRedirectsToKeycloakAndUsesS256Pkce()
    {
        var baseUrl = Environment.GetEnvironmentVariable("RYZEAUTH_E2E_BASE_URL") ?? "http://localhost:8080";
        var page = await _browser.NewPageAsync();
        var authorize = baseUrl + "/realms/ryzespace/protocol/openid-connect/auth" +
            "?client_id=ryzeauth-web&redirect_uri=https%3A%2F%2Fapp.ryze.localhost%2Fcallback&response_type=code&scope=openid" +
            "&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN012&code_challenge_method=S256";

        await page.GotoAsync(authorize, new PageGotoOptions { WaitUntil = WaitUntilState.DOMContentLoaded });

        page.Url.Should().Contain("/realms/ryzespace/");
        (await page.Locator("input[type=password]").CountAsync()).Should().BeGreaterThan(0);
        page.Url.Should().NotContain("app.ryze.localhost");
    }
}
