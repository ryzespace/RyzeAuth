package space.ryze.auth.magic;

import jakarta.ws.rs.core.Response;
import java.util.Collections;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class MagicLinkActionTokenHandler extends AbstractActionTokenHandler<MagicLinkActionToken> {
    public MagicLinkActionTokenHandler() {
        super(MagicLinkActionToken.TOKEN_TYPE, MagicLinkActionToken.class, Messages.STALE_VERIFY_EMAIL_LINK, EventType.LOGIN, Errors.INVALID_TOKEN);
    }

    @Override
    public Predicate<? super MagicLinkActionToken>[] getVerifiers(ActionTokenContext<MagicLinkActionToken> context) {
        return TokenUtils.predicates(verifyEmail(context));
    }

    @Override
    public Response handleToken(MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> context) {
        var session = context.getSession();
        var realm = context.getRealm();
        var currentSession = context.getAuthenticationSession();
        var user = session.users().getUserById(realm, token.getSubject());
        if (user == null) {
            return context.getSession().getProvider(LoginFormsProvider.class).setError(Messages.INVALID_USER).createErrorPage(Response.Status.BAD_REQUEST);
        }

        context.getEvent().event(EventType.LOGIN).detail(Details.EMAIL, user.getEmail()).success();
        var compoundId = AuthenticationSessionCompoundId.encoded(token.getCompoundAuthenticationSessionId());
        var manager = new AuthenticationSessionManager(session);
        var client = realm.getClientById(compoundId.getClientUUID());
        AuthenticationSessionModel original = client == null ? null : manager.getAuthenticationSessionByIdAndClient(realm, compoundId.getRootSessionId(), client, compoundId.getTabId());
        if (original != null) {
            original.setAuthNote(MagicLinkAuthenticator.VERIFIED_NOTE, user.getEmail());
        } else {
            session.authenticationSessions().updateNonlocalSessionAuthNotes(compoundId, Collections.singletonMap(MagicLinkAuthenticator.VERIFIED_NOTE, user.getEmail()));
        }

        return session.getProvider(LoginFormsProvider.class)
            .setAuthenticationSession(currentSession)
            .setSuccess(Messages.EMAIL_VERIFIED, user.getEmail())
            .createInfoPage();
    }

    @Override
    public boolean canUseTokenRepeatedly(MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> context) {
        return false;
    }
}
