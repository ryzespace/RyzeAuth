FROM maven:3.9.9-eclipse-temurin-21 AS extensions
WORKDIR /workspace
COPY keycloak-extensions/ryzeauth-security-events ./ryzeauth-security-events
COPY keycloak-extensions/ryzeauth-magic-link ./ryzeauth-magic-link
COPY keycloak-extensions/ryzeauth-adaptive-mfa ./ryzeauth-adaptive-mfa
COPY keycloak-extensions/ryzeauth-hibp-password-policy ./ryzeauth-hibp-password-policy
RUN mvn -q -f ryzeauth-security-events/pom.xml -DskipTests package
RUN mvn -q -f ryzeauth-magic-link/pom.xml -DskipTests package
RUN mvn -q -f ryzeauth-adaptive-mfa/pom.xml -DskipTests package
RUN mvn -q -f ryzeauth-hibp-password-policy/pom.xml -DskipTests package

FROM quay.io/keycloak/keycloak:26.1.2
COPY --from=extensions /workspace/ryzeauth-security-events/target/ryzeauth-security-events-1.0.0.jar /opt/keycloak/providers/
COPY --from=extensions /workspace/ryzeauth-magic-link/target/ryzeauth-magic-link-1.0.0.jar /opt/keycloak/providers/
COPY --from=extensions /workspace/ryzeauth-adaptive-mfa/target/ryzeauth-adaptive-mfa-1.0.0.jar /opt/keycloak/providers/
COPY --from=extensions /workspace/ryzeauth-hibp-password-policy/target/ryzeauth-hibp-password-policy-1.0.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
