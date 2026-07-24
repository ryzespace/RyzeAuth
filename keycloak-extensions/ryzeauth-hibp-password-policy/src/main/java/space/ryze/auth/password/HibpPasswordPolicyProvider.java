package space.ryze.auth.password;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

public final class HibpPasswordPolicyProvider implements PasswordPolicyProvider {
    private final HttpClient client = HttpClient.newBuilder().build();

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return validate(password, null);
    }

    @Override
    public PolicyError validate(String password, String configuredValue) {
        if (password == null || password.isBlank()) {
            return null;
        }

        try {
            var digest = sha1(password);
            var prefix = digest.substring(0, 5);
            var suffix = digest.substring(5);
            var request = HttpRequest.newBuilder(URI.create("https://api.pwnedpasswords.com/range/" + prefix))
                .header("Add-Padding", "true")
                .header("User-Agent", "RyzeAuth-Keycloak-Policy/1.0")
                .GET()
                .build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                return new PolicyError("hibpUnavailable");
            }

            for (var line : response.body().split("\\R")) {
                var separator = line.indexOf(':');
                if (separator > 0 && suffix.equalsIgnoreCase(line.substring(0, separator).trim())) {
                    return new PolicyError("hibpBreachedPassword");
                }
            }

            return null;
        } catch (Exception exception) {
            return new PolicyError("hibpUnavailable");
        }
    }

    @Override
    public Object parseConfig(String value) {
        return value;
    }

    @Override
    public void close() {
    }

    private static String sha1(String password) throws Exception {
        var digest = MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8));
        var output = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            output.append(String.format(Locale.ROOT, "%02X", item));
        }
        return output.toString();
    }
}
