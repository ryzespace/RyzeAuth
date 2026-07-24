# Keycloak Signing Key Templates

Use `eddsa-v1.json` as the preferred signing-key component and `es256-v1.json` where ES256 compatibility is required. Keycloak already provides an RSA-generated provider for RS256 compatibility.

Import a component through the Keycloak Admin API or Realm Settings -> Keys. Confirm that the active key appears in JWKS with a unique `kid`. Keep the previous key passive until access-token lifetime, clock skew, and JWKS cache duration have elapsed. Use a new component name for every rotation.
