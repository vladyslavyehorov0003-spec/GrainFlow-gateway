package com.grainflow.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * Fetches OpenAPI specs from each downstream service, rewrites the "servers" field
 * to point at this gateway (/api/v1), and returns the modified spec.
 *
 * Result: Swagger UI's "Try it out" sends requests through the gateway — auth works,
 * routing works, exactly as in production.
 */
@Slf4j
@RestController
public class SwaggerAggregatorController {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestClient restClient = RestClient.create();

    @Value("${services.auth.url}")
    private String authUrl;

    @Value("${services.warehouse.url}")
    private String warehouseUrl;

    @Value("${services.payment.url}")
    private String paymentUrl;

    @GetMapping(value = "/v3/api-docs/auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> authDocs() {
        return proxyDocs(authUrl, "Auth Service");
    }

    @GetMapping(value = "/v3/api-docs/warehouse", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> warehouseDocs() {
        return proxyDocs(warehouseUrl, "Warehouse Service");
    }

    @GetMapping(value = "/v3/api-docs/payments", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> paymentsDocs() {
        return proxyDocs(paymentUrl, "Payment Service");
    }

    // ── private ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private ResponseEntity<String> proxyDocs(String serviceUrl, String serviceName) {
        try {
            // Each service has context-path=/api/v1, so api-docs live at /api/v1/v3/api-docs
            String json = restClient.get()
                    .uri(serviceUrl + "/api/v1/v3/api-docs")
                    .retrieve()
                    .body(String.class);

            Map<String, Object> spec = objectMapper.readValue(json, Map.class);

            // Rewrite servers so Swagger UI "Try it out" sends requests through this gateway.
            // Path in spec = /batches, server = /api/v1  →  full URL = /api/v1/batches → gateway → service ✓
            spec.put("servers", List.of(
                    Map.of("url", "/api/v1", "description", "API Gateway (" + serviceName + ")")
            ));

            return ResponseEntity.ok(objectMapper.writeValueAsString(spec));

        } catch (Exception e) {
            log.error("Failed to fetch API docs for {} from {}: {}", serviceName, serviceUrl, e.getMessage());
            return ResponseEntity.status(503)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"Docs unavailable — " + serviceName + " is not responding\"}");
        }
    }
}
