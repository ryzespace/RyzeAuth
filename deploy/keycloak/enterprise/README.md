# Enterprise Federation Templates

Import the SAML identity-provider template only after replacing every example URL, certificate, and issuer value. Keep the provider disabled until metadata signature, assertion signature, encryption, NameID mapping, and logout behavior are tested in staging.

Use the JIT mapper template with the Keycloak first-broker-login flow. Map a verified enterprise email to the Keycloak profile, require email verification when the upstream assertion cannot be trusted, and assign organization membership through a reviewed provisioning policy.

SCIM 2.0 is exposed by RyzeAuth at `/scim/v2/Users`. Create a Keycloak confidential service client with `scim:users:read` and `scim:users:write` scopes, an audience of `ryzeauth-api`, and no browser, implicit, or direct-grant flows. The client needs no Keycloak administrative realm roles; RyzeAuth uses its separate least-privilege administrative service account.
