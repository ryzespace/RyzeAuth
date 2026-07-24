package space.ryze.auth.magic;

import org.keycloak.authentication.actiontoken.DefaultActionToken;

public final class MagicLinkActionToken extends DefaultActionToken {
    public static final String TOKEN_TYPE = "ryzeauth-magic-link";

    public MagicLinkActionToken(String userId, int expiration, String authenticationSessionId, String email, String clientId) {
        super(userId, TOKEN_TYPE, expiration, null, authenticationSessionId);
        this.issuedFor = clientId;
        setEmail(email);
    }

    private MagicLinkActionToken() {
    }
}
