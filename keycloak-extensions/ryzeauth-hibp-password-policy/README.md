# RyzeAuth HIBP Password Policy

The provider uses the Have I Been Pwned range API. It sends only the first five hexadecimal characters of a SHA-1 digest as required by the k-anonymity protocol. It does not store a password or use SHA-1 as a password authentication hash.

The provider fails closed when the breach service is unavailable. Build with Java 21 and Maven, copy the JAR to `/opt/keycloak/providers`, run `kc.sh build`, and restart Keycloak. Enable `hibpBreach()` in the realm password policy after deployment.
