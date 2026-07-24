package space.ryze.auth.risk;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public final class TurnstileGateAuthenticatorFactory implements AuthenticatorFactory {
    private static final TurnstileGateAuthenticator INSTANCE = new TurnstileGateAuthenticator();

    @Override
    public String getId() { return "ryzeauth-turnstile-gate"; }
    @Override
    public String getDisplayType() { return "RyzeAuth Turnstile Gate"; }
    @Override
    public String getReferenceCategory() { return "captcha"; }
    @Override
    public boolean isConfigurable() { return false; }
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED }; }
    @Override
    public boolean isUserSetupAllowed() { return false; }
    @Override
    public String getHelpText() { return "Requires Cloudflare Turnstile only when RyzeAuth risk score reaches the CAPTCHA threshold."; }
    @Override
    public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    @Override
    public Authenticator create(KeycloakSession session) { return INSTANCE; }
    @Override
    public void init(Config.Scope config) { }
    @Override
    public void postInit(KeycloakSessionFactory factory) { }
    @Override
    public void close() { }
}
