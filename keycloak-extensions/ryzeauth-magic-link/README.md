# RyzeAuth Magic Link Extension

Build with Java 21 and Maven:

```bash
mvn clean package
```

Copy the generated JAR to `/opt/keycloak/providers/`, run `kc.sh build`, and restart Keycloak. In the Keycloak authentication flow, place `Username Form` before `RyzeAuth Magic Link`. Configure SMTP and set the custom action-token lifespan for `ryzeauth-magic-link` to 10 or 15 minutes.

The extension issues a one-time Keycloak action token. It does not share the opaque password-reset ticket implementation and does not expose user passwords to RyzeAuth API.
