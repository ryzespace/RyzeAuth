package space.ryze.auth.magic;

import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class MagicLinkAuthenticator implements Authenticator {
    public static final String VERIFIED_NOTE = "RYZEAUTH_MAGIC_LINK_VERIFIED";
    private static final String SENT_NOTE = "RYZEAUTH_MAGIC_LINK_SENT";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        var user = context.getUser();
        var realm = context.getRealm();
        if (user == null || user.getEmail() == null || realm.getSmtpConfig().isEmpty()) {
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, context.form().createErrorPage(Response.Status.BAD_REQUEST));
            return;
        }

        var authSession = context.getAuthenticationSession();
        if (Objects.equals(authSession.getAuthNote(VERIFIED_NOTE), user.getEmail())) {
            context.success();
            return;
        }

        if (!Objects.equals(authSession.getAuthNote(SENT_NOTE), user.getEmail())) {
            authSession.setAuthNote(SENT_NOTE, user.getEmail());
            send(context, user);
            return;
        }

        challenge(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (Objects.equals(context.getAuthenticationSession().getAuthNote(VERIFIED_NOTE), context.getUser().getEmail())) {
            context.success();
            return;
        }

        var action = context.getHttpRequest().getDecodedFormParameters().getFirst("submitAction");
        if ("resend".equals(action)) {
            send(context, context.getUser());
            return;
        }

        challenge(context);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private void send(AuthenticationFlowContext context, UserModel user) {
        var session = context.getSession();
        var realm = context.getRealm();
        var authSession = context.getAuthenticationSession();
        var lifespan = realm.getActionTokenGeneratedByUserLifespan(MagicLinkActionToken.TOKEN_TYPE);
        var expiration = Time.currentTime() + lifespan;
        var compoundId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
        var token = new MagicLinkActionToken(user.getId(), expiration, compoundId, user.getEmail(), authSession.getClient().getClientId());
        var link = Urls.actionTokenBuilder(session.getContext().getUri().getBaseUri(), token.serialize(session, realm, session.getContext().getUri()), authSession.getClient().getClientId(), authSession.getTabId(), null).build(realm.getName()).toString();
        var attributes = new HashMap<String, Object>();
        attributes.put("link", link);
        attributes.put("expirationInMinutes", TimeUnit.SECONDS.toMinutes(lifespan));
        attributes.put("realmName", realm.getDisplayName());
        try {
            session.getProvider(org.keycloak.email.EmailTemplateProvider.class)
                .setRealm(realm)
                .setUser(user)
                .setAuthenticationSession(authSession)
                .send("magicLinkSubject", "magic-link-email.ftl", attributes);
            challenge(context);
        } catch (org.keycloak.email.EmailException exception) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form().createErrorPage(Response.Status.SERVICE_UNAVAILABLE));
        }
    }

    private void challenge(AuthenticationFlowContext context) {
        var response = context.form()
            .setActionUri(context.getActionUrl(context.generateAccessCode()))
            .setExecution(context.getExecution().getId())
            .createForm("magic-link-form.ftl");
        context.forceChallenge(response);
    }
}
