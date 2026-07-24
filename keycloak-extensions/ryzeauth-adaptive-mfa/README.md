# RyzeAuth Adaptive MFA Extension

Build with Java 21 and Maven, copy the generated JAR to `/opt/keycloak/providers/`, run `kc.sh build`, and restart Keycloak.

Set these Keycloak environment variables:

```text
RYZEAUTH_RISK_ENDPOINT=https://api-auth.ryzespace.example/internal/keycloak/risk-assessments
RYZEAUTH_EVENT_SIGNING_KEY=<base64-encoded-32-byte-secret>
```

Add `RyzeAuth Risk Step-Up` after user identification, followed by `RyzeAuth Turnstile Gate`. Create a conditional subflow containing `Condition - RyzeAuth Risk Step-Up`, TOTP, and WebAuthn authenticators. The condition executes the MFA subflow only when the risk API requests a step-up. Set `RYZEAUTH_TURNSTILE_SITE_KEY`, `RYZEAUTH_TURNSTILE_SECRET_KEY`, and an optional `RYZEAUTH_CAPTCHA_RISK_THRESHOLD`. The gate appears only after the configured risk threshold. The extension fails closed by setting both `requireMfa` and `block` when the risk API cannot be reached.
