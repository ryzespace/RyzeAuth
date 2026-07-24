package space.ryze.auth.risk;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public final class RiskStepUpCondition implements ConditionalAuthenticator {
    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        return Boolean.parseBoolean(context.getAuthenticationSession().getAuthNote(RiskStepUpAuthenticator.STEP_UP_NOTE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
