package space.ryze.auth.risk;

import jakarta.ws.rs.core.Response;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class TurnstileGateAuthenticator implements Authenticator {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final String siteKey = System.getenv("RYZEAUTH_TURNSTILE_SITE_KEY");
    private final String secretKey = System.getenv("RYZEAUTH_TURNSTILE_SECRET_KEY");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!Boolean.parseBoolean(context.getAuthenticationSession().getAuthNote(RiskStepUpAuthenticator.CAPTCHA_NOTE))) {
            context.success();
            return;
        }

        if (siteKey == null || siteKey.isBlank() || secretKey == null || secretKey.isBlank()) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form().createErrorPage(Response.Status.SERVICE_UNAVAILABLE));
            return;
        }

        challenge(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        var token = context.getHttpRequest().getDecodedFormParameters().getFirst("cf-turnstile-response");
        if (verify(token, context.getConnection().getRemoteAddr())) {
            context.success();
            return;
        }

        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, context.form().setError("captchaFailed").createForm("turnstile-gate.ftl"));
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private void challenge(AuthenticationFlowContext context) {
        context.forceChallenge(context.form()
            .setAttribute("turnstileSiteKey", siteKey)
            .setActionUri(context.getActionUrl(context.generateAccessCode()))
            .setExecution(context.getExecution().getId())
            .createForm("turnstile-gate.ftl"));
    }

    private boolean verify(String token, String remoteIp) {
        if (token == null || token.isBlank()) {
            return false;
        }

        try {
            var body = "secret=" + encoded(secretKey) + "&response=" + encoded(token) + "&remoteip=" + encoded(remoteIp);
            var request = HttpRequest.newBuilder(java.net.URI.create("https://challenges.cloudflare.com/turnstile/v0/siteverify"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return response.statusCode() == 200 && response.body().contains("\"success\":true");
        } catch (Exception exception) {
            return false;
        }
    }

    private static String encoded(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
