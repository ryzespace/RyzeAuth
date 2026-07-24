package space.ryze.auth.risk;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class RiskApiClient {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final String endpoint = System.getenv("RYZEAUTH_RISK_ENDPOINT");
    private final String signingKey = System.getenv("RYZEAUTH_EVENT_SIGNING_KEY");

    public RiskDecision assess(String subjectId, String ipAddress, String userAgent, String deviceId) {
        if (endpoint == null || endpoint.isBlank() || signingKey == null || signingKey.isBlank()) {
            return new RiskDecision(100, true, true);
        }

        var payload = "{\"subjectId\":\"" + escape(subjectId)
            + "\",\"ipAddress\":" + json(ipAddress)
            + ",\"userAgent\":" + json(userAgent)
            + ",\"deviceId\":" + json(deviceId)
            + ",\"occurredAt\":\"" + Instant.now() + "\"}";
        try {
            var request = HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .header("X-RyzeAuth-Signature", signature(payload))
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                return new RiskDecision(100, true, true);
            }

            return new RiskDecision(score(response.body()), response.body().contains("\"requireMfa\":true"), response.body().contains("\"block\":true"));
        } catch (Exception exception) {
            return new RiskDecision(100, true, true);
        }
    }

    private String signature(String payload) throws NoSuchAlgorithmException, InvalidKeyException {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(signingKey), "HmacSHA256"));
        var bytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        var output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            output.append(String.format("%02x", value));
        }
        return output.toString();
    }

    private static String json(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static int score(String value) {
        var marker = "\"score\":";
        var start = value.indexOf(marker);
        if (start < 0) {
            return 100;
        }

        start += marker.length();
        var end = start;
        while (end < value.length() && Character.isDigit(value.charAt(end))) {
            end++;
        }
        try {
            return Integer.parseInt(value.substring(start, end));
        } catch (RuntimeException exception) {
            return 100;
        }
    }

    public record RiskDecision(int score, boolean requireMfa, boolean block) {
    }
}
