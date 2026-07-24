package space.ryze.auth.events;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;

public final class RyzeAuthEventListenerProvider implements EventListenerProvider {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final String endpoint = System.getenv("RYZEAUTH_EVENT_ENDPOINT");
    private final String signingKey = System.getenv("RYZEAUTH_EVENT_SIGNING_KEY");

    @Override
    public void onEvent(Event event) {
        if (endpoint == null || endpoint.isBlank() || signingKey == null || signingKey.isBlank() || event.getUserId() == null) {
            return;
        }

        var details = event.getDetails();
        var deviceId = details == null ? null : details.get("device_id");
        var userAgent = details == null ? null : details.get("user_agent");
        var body = "{\"eventType\":\"" + escape(event.getType().name())
            + "\",\"subjectId\":\"" + escape(event.getUserId())
            + "\",\"sessionId\":" + json(event.getSessionId())
            + ",\"deviceId\":" + json(deviceId)
            + ",\"ipAddress\":" + json(event.getIpAddress())
            + ",\"userAgent\":" + json(userAgent)
            + ",\"occurredAt\":\"" + Instant.now() + "\"}";
        try {
            var request = HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .header("X-RyzeAuth-Signature", signature(body))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding());
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeyException ignored) {
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    }

    @Override
    public void close() {
    }

    private String signature(String payload) throws NoSuchAlgorithmException, InvalidKeyException {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(java.util.Base64.getDecoder().decode(signingKey), "HmacSHA256"));
        var digest = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        var value = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            value.append(String.format("%02x", item));
        }
        return value.toString();
    }

    private static String json(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
