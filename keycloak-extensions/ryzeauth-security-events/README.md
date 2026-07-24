# RyzeAuth Keycloak Security Events Extension

Build the extension with Java 21 and Maven:

```bash
mvn clean package
```

Copy `target/ryzeauth-security-events-1.0.0.jar` to `/opt/keycloak/providers/`, run `kc.sh build`, and restart Keycloak. Configure these environment variables on Keycloak:

```text
RYZEAUTH_EVENT_ENDPOINT=https://api-auth.ryzespace.example/internal/keycloak/events
RYZEAUTH_EVENT_SIGNING_KEY=<base64-encoded-32-byte-secret>
```

Add `ryzeauth-security-events` to the realm event listeners after the provider is installed. The signing key must match `Security:KeycloakEventSigningKey` in RyzeAuth API. The endpoint accepts only HMAC-SHA-256 signed payloads within a five-minute timestamp window.
