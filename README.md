# RyzeAuth

RyzeAuth is an authentication control plane for RyzeSpace services. It does not implement a separate login engine: **Keycloak** is the identity, credential, OIDC session, MFA, passkey, and SSO authority. The ASP.NET Core API provides organization RBAC/ABAC, scoped API keys, audit records, opaque password-reset tickets, and internal gRPC API-key introspection.

> This repository is a production-oriented foundation. Complete the mandatory deployment checklist in [`docs/KEYCLOAK-HARDENING.md`](docs/KEYCLOAK-HARDENING.md) before production use, including production hostnames, TLS, secrets, service-account roles, and the CAPTCHA/SCIM/risk adapters.

## Architecture

```text
Browser / mobile / desktop
          | Authorization Code + PKCE / OIDC
          v
 Keycloak (ryzespace realm) ------------> SMTP / security events
          | JWT (EdDSA / ES256 / RS256, JWKS + kid)
          v
RyzeAuth API (.NET 10) ---- gRPC ---- RyzeSpace services
    |          |
    |          +-- PostgreSQL: organizations, RBAC/ABAC, API keys, audit, reset tickets, devices
    +-- Redis: distributed limits, risk signals, Data Protection keys
    +-- OpenTelemetry: OTLP / Prometheus
    +-- Keycloak Admin API: credential reset and global logout
```

The solution uses Clean Architecture: `Api -> Application -> Domain <- Infrastructure`. MediatR handles commands, queries, and validation behavior. PostgreSQL is accessed through EF Core/Npgsql with Fluent API mappings and EF Core migrations.

## Local startup

Requirements: Docker Compose and the .NET SDK specified by [`global.json`](global.json). The Compose setup is development-only because Keycloak uses `start-dev` and HTTP. Production requires Keycloak `start`, HTTPS, and a hardened ingress.

```bash
cp .env.example .env
openssl rand -base64 32
openssl rand -base64 32
```

Put the first generated value into `TOKEN_DIGEST_KEY` and the second into `KEYCLOAK_EVENT_SIGNING_KEY` in `.env`, set unique passwords, and start the stack:

```bash
docker compose up --build
```

| Service | Address |
|---|---|
| Keycloak | `http://localhost:8080` |
| RyzeAuth API | `http://localhost:8081` |
| OpenAPI | `http://localhost:8081/openapi/v1.json` |
| Scalar | `http://localhost:8081/scalar/v1` |
| Liveness | `http://localhost:8081/health/live` |
| Prometheus | `http://localhost:8081/metrics` |

The initial realm import creates a development-only `ryzeauth-admin` client secret. Rotate it outside local Compose. Assign its service account only the `realm-management` client roles `query-users`, `view-users`, and `manage-users`.

## Tests

```bash
dotnet test tests/RyzeAuth.UnitTests
dotnet test tests/RyzeAuth.IntegrationTests
pwsh tests/RyzeAuth.E2ETests/bin/Debug/net10.0/playwright.ps1 install chromium
dotnet test tests/RyzeAuth.E2ETests
```

Integration tests use PostgreSQL through Testcontainers. E2E tests run against Keycloak and Chromium. GitHub Actions builds the solution, runs unit, integration, and E2E checks, builds the Keycloak extensions with Java 21, and executes the independent ecosystem smoke tester.

## Independent ecosystem tester

[`tools/RyzeAuth.EcosystemTester`](tools/RyzeAuth.EcosystemTester) is a standalone black-box console verifier. It has no project references, no external packages, and no direct access to PostgreSQL, Redis, or the Keycloak Admin API. It validates public HTTP, OIDC, and JWKS contracts.

```bash
dotnet run --project tools/RyzeAuth.EcosystemTester -- \
  --api http://localhost:8081 \
  --authority http://localhost:8080/realms/ryzespace \
  --allow-http \
  --report artifacts/ryzeauth-smoke.json
```

See [`docs/ECOSYSTEM-TESTER.md`](docs/ECOSYSTEM-TESTER.md) for passive checks, opt-in active checks, exit codes, and CI usage.

## Security model

### Keycloak responsibilities

- **Passwords:** the realm requires `hashAlgorithm(argon2)` for Keycloak Argon2id, a minimum length of 12, password history, username/email restrictions, and the `hibpBreach` Keycloak password-policy provider. RyzeAuth never stores, encrypts, or hashes user passwords. MD5 and SHA-256 are never used as password mechanisms. An optional pepper requires a dedicated `PasswordHashProvider` backed by HSM or Vault.
- **OIDC, OAuth 2.1, and SSO:** Authorization Code is the only browser flow. Implicit flow and Resource Owner Password Credentials are disabled. The `ryzeauth-web` public client requires S256 PKCE. Access tokens last 10 minutes, sessions and refresh tokens last at most 30 days, and refresh rotation is enabled with `revokeRefreshToken=true` and `refreshTokenMaxReuse=0`.
- **MFA:** TOTP, recovery authentication codes, WebAuthn/passkeys, and FIDO2/YubiKey are configured. SMS is neither the only nor the default MFA method.
- **Brute force and events:** Keycloak blocks after five failures for up to 15 minutes. Login, password, email, MFA, registration, and account-deletion events are retained for 30 days in the Keycloak event store.
- **JWTs:** consumers use Keycloak JWKS and validate `iss`, `aud`, `exp`, `nbf`, and `kid`. Services do not share an HS256 secret.

### RyzeAuth API responsibilities

- API keys use `rza_<prefix>.<256-bit-secret>`, scopes, and optional expiry. The secret is returned only once; PostgreSQL stores an HMAC-SHA-256 digest using a separate server key. This protects a high-entropy API secret and is not password hashing.
- Password reset uses an opaque, one-time, URL-safe 256-bit token, stored only as an HMAC digest and valid for 15 minutes. Unknown emails receive the same response. Completion delegates the credential change to Keycloak and revokes all sessions.
- Organizations, `Owner`/`OrgAdmin`/`SecurityAdmin`/`Member` roles, teams, and JSON ABAC attributes are stored in PostgreSQL. Management actions require membership authorization.
- Redis stores distributed, HMAC-keyed risk signals, JWT revocation state, and atomic rate-limit counters. Password-reset initiation and completion are independently limited to five requests per IP every 15 minutes.
- The application audit trail is append-only in `security_audit_events`. A PostgreSQL trigger rejects update and delete operations, while Keycloak retains authentication and administrative events.

## Primary API routes

| Method | Route | Protection |
|---|---|---|
| `POST` | `/v1/password-resets` | Anonymous, IP-limited, always returns 202 to prevent account enumeration |
| `POST` | `/v1/password-resets/complete` | Anonymous, opaque one-time token and password policy |
| `POST` | `/v1/organizations` | Keycloak JWT |
| `POST` | `/v1/organizations/{id}/members` | Owner or OrgAdmin RBAC |
| `POST` | `/v1/organizations/{id}/api-keys` | RBAC, secret returned once, `Cache-Control: no-store` |
| `DELETE` | `/v1/organizations/{id}/api-keys/{keyId}` | RBAC, immediate revocation |
| `GET` | `/v1/me/security-history` | Keycloak JWT, user-visible immutable security events |
| `GET` | `/v1/organizations/{id}/audit` | Organization RBAC, immutable organization audit events |
| `GET` | `/v1/me/devices` | Keycloak JWT, active device sessions |
| `PATCH` | `/v1/me/devices/{deviceId}` | Recent authentication, rename or trust the caller's device |
| `DELETE` | `/v1/me/devices/{deviceId}` | Keycloak JWT, local and Keycloak-session revocation |
| `POST` | `/v1/me/tokens/revoke` | Keycloak JWT, Redis-backed current-token blacklist |
| `POST` | `/v1/me/sessions/revoke-all` | Keycloak JWT, global Keycloak logout and subject revocation watermark |
| `POST` | `/internal/tokens/introspect` | Internal service identity, Keycloak token introspection |
| `GET/POST/PUT/DELETE` | `/scim/v2/Users` | `scim:users:read` or `scim:users:write` OAuth scopes |
| gRPC | `ApiKeyIntrospection.Introspect` | `azp=ryzeauth-internal` service token and mTLS/service-mesh policy |

## Extended capability status

| Capability | Implementation | Production requirement |
|---|---|---|
| Passkeys, WebAuthn, YubiKey, TOTP, recovery codes | Keycloak realm configuration | Set the real RP ID and enable the required actions for the intended user groups |
| Passwordless magic links | `keycloak-extensions/ryzeauth-magic-link` | Deploy the provider, configure SMTP, and use a 10-15 minute single-use action-token lifetime |
| OAuth 2.1, OIDC, SSO, PKCE | Keycloak realm | Use a BFF or Authorization Code with PKCE for public web clients |
| JWT revocation, blacklist, introspection | Redis blacklist, Keycloak logout, internal Keycloak introspection route | Use JWT by default; allow internal reference-token introspection only through service identity and mTLS |
| HttpOnly cookies and CSRF | BFF deployment pattern | BFF cookies require `HttpOnly`, `Secure`, `SameSite=Lax/Strict`, antiforgery, and Origin/Referer checks |
| CAPTCHA after failures | Keycloak browser flow with hCaptcha or Turnstile adapter | Enable only after the failure threshold and use Redis or Keycloak distributed cache |
| Device sessions, trust, and limit | Signed Keycloak event listener plus RyzeAuth device API | Deploy the event provider and keep device binding optional and privacy-reviewed |
| Geo-IP, credential stuffing, ATO, and adaptive MFA | Provider contract, Redis risk counters, impossible-travel detection, adaptive MFA extension | Choose MaxMind or a commercial provider through the contract and deploy the Keycloak risk provider |
| SCIM 2.0, SAML, JIT, delegated administration | SCIM routes and enterprise Keycloak templates | Replace placeholders, configure client scopes, validate SAML metadata, and apply reviewed organization roles |
| Login anomalies and alerts | Keycloak Event Store, RyzeAuth audit, Redis | Forward signals to Loki/Seq and alert on suspicious patterns without logging secrets, MFA codes, or full IP addresses |

Authentication flow setup, magic links, adaptive MFA, token strategy, device sessions, SCIM, SAML, JIT, and delegated administration are described in [`docs/AUTHENTICATION-FLOWS.md`](docs/AUTHENTICATION-FLOWS.md). Key templates for EdDSA, ES256, and RS256 compatibility are in [`deploy/keycloak/keys`](deploy/keycloak/keys). The deployment controls, key rotation process, BFF CSRF model, CSP, TLS, CAPTCHA, device policy, and release gate are in [`docs/KEYCLOAK-HARDENING.md`](docs/KEYCLOAK-HARDENING.md).
