package space.ryze.auth.password;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

public final class HibpPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
    @Override
    public String getId() { return "hibpBreach"; }
    @Override
    public String getDisplayName() { return "Have I Been Pwned breach check"; }
    @Override
    public String getConfigType() { return PasswordPolicyProvider.STRING_CONFIG_TYPE; }
    @Override
    public String getDefaultConfigValue() { return ""; }
    @Override
    public boolean isMultiplSupported() { return false; }
    @Override
    public PasswordPolicyProvider create(KeycloakSession session) { return new HibpPasswordPolicyProvider(); }
    @Override
    public void init(Config.Scope config) { }
    @Override
    public void postInit(KeycloakSessionFactory factory) { }
    @Override
    public void close() { }
}
