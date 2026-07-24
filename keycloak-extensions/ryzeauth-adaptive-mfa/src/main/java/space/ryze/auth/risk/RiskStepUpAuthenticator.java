package space.ryze.auth.risk;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class RiskStepUpAuthenticator implements Authenticator {
    public static final String STEP_UP_NOTE = "RYZEAUTH_REQUIRE_STEP_UP";
    public static final String CAPTCHA_NOTE = "RYZEAUTH_REQUIRE_CAPTCHA";
    private final RiskApiClient risk = new RiskApiClient();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        var user = context.getUser();
        if (user == null) {
            context.attempted();
            return;
        }

        var ip = context.getConnection().getRemoteAddr();
        var userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
        var decision = risk.assess(user.getId(), ip, userAgent, null);
        if (decision.block()) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED, context.form().createErrorPage(Response.Status.FORBIDDEN));
            return;
        }

        context.getAuthenticationSession().setAuthNote(STEP_UP_NOTE, Boolean.toString(decision.requireMfa()));
        context.getAuthenticationSession().setAuthNote(CAPTCHA_NOTE, Boolean.toString(decision.score() >= captchaThreshold()));
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
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

    private static int captchaThreshold() {
        try {
            return Integer.parseInt(System.getenv().getOrDefault("RYZEAUTH_CAPTCHA_RISK_THRESHOLD", "50"));
        } catch (NumberFormatException exception) {
            return 50;
        }
    }
}
