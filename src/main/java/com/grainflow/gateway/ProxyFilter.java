package com.grainflow.gateway;

import com.grainflow.gateway.security.AuthClient;
import com.grainflow.gateway.security.ValidateResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

@Slf4j
@Component
@Order(1)
public class ProxyFilter extends OncePerRequestFilter {

    // Hop-by-hop / framework headers we never forward
    private static final Set<String> SKIP_HEADERS = Set.of(
            "host", "content-length", "transfer-encoding"
    );

    // Public routes — no token required, gateway just proxies through
    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/verify",
            "/api/v1/auth/resend-verification",
            "/api/v1/payments/webhook",
            "/swagger-ui",
            "/v3/api-docs",
            "/actuator/health"
    );

    // Trusted headers we inject for downstream services.
    // CRITICAL: stripped from every incoming request to prevent client spoofing.
    private static final Set<String> INTERNAL_HEADERS = Set.of(
            "x-user-id",
            "x-company-id",
            "x-email",
            "x-role",
            "x-company-verified",
            "x-subscription-status"
    );

    private final RestClient restClient;
    private final AuthClient authClient;

    @Value("${services.auth.url}")
    private String authUrl;

    @Value("${services.warehouse.url}")
    private String warehouseUrl;

    @Value("${services.payment.url}")
    private String paymentUrl;

    public ProxyFilter(AuthClient authClient) {
        this.restClient = RestClient.create();
        this.authClient = authClient;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String targetBase = resolveTarget(path);

        // Path is not for any backend service — let Spring handle it (404, actuator, etc.)
        if (targetBase == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // ── Auth: validate token for protected routes ─────────────────────────
        ValidateResponse validated = null;
        if (!isPublicPath(path)) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                writeUnauthorized(response, "Missing token");
                return;
            }

            validated = authClient.validate(authHeader);
            if (!validated.valid()) {
                writeUnauthorized(response, "Invalid or expired token");
                return;
            }
        }

        // ── Build upstream request ────────────────────────────────────────────
        String query = request.getQueryString();
        String targetUrl = targetBase + path + (query != null ? "?" + query : "");
        String method = request.getMethod();

        log.debug("[PROXY] {} {} → {}", method, path, targetUrl);

        byte[] requestBody = request.getInputStream().readAllBytes();
        ValidateResponse trusted = validated; // effectively final for lambda

        ResponseEntity<byte[]> upstream;
        try {
            upstream = restClient
                    .method(HttpMethod.valueOf(method))
                    .uri(targetUrl)
                    .headers(h -> {
                        // Copy original headers, stripping:
                        //  - hop-by-hop (host, content-length, etc.)
                        //  - any client-supplied X-User-* etc. (spoofing protection)
                        Collections.list(request.getHeaderNames()).stream()
                                .filter(name -> {
                                    String lower = name.toLowerCase();
                                    return !SKIP_HEADERS.contains(lower)
                                            && !INTERNAL_HEADERS.contains(lower);
                                })
                                .forEach(name -> h.add(name, request.getHeader(name)));

                        // Inject trusted user context for protected routes
                        if (trusted != null) {
                            h.add("X-User-Id",             trusted.userId().toString());
                            h.add("X-Company-Id",          trusted.companyId().toString());
                            h.add("X-Email",               trusted.email());
                            h.add("X-Role",                trusted.role());
                            h.add("X-Company-Verified",    String.valueOf(trusted.companyVerified()));
                            h.add("X-Subscription-Status", trusted.subscriptionStatus());
                        }
                    })
                    .body(requestBody)
                    .exchange((req, res) -> {
                        // Read body defensively — on 4xx/5xx some clients close streams early.
                        // We want to pass the upstream status + body through regardless.
                        byte[] body;
                        try {
                            body = res.getBody().readAllBytes();
                        } catch (IOException ex) {
                            log.warn("[PROXY] failed to read upstream body ({}): {}",
                                    res.getStatusCode().value(), ex.getMessage());
                            body = new byte[0];
                        }
                        return ResponseEntity.status(res.getStatusCode())
                                .headers(res.getHeaders())
                                .body(body);
                    });
        } catch (Exception e) {
            // Real connection failure — service is down or unreachable
            log.error("[PROXY] {} {} → {} CONNECTION FAILED", method, path, targetUrl, e);
            response.setStatus(502);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"status\":\"error\",\"message\":\"Service temporarily unavailable\",\"data\":null}"
            );
            return;
        }

        log.debug("[PROXY] {} {} ← {}", method, path, upstream.getStatusCode().value());

        response.setStatus(upstream.getStatusCode().value());
        upstream.getHeaders().forEach((name, values) -> {
            if (!SKIP_HEADERS.contains(name.toLowerCase())) {
                values.forEach(value -> response.addHeader(name, value));
            }
        });

        byte[] body = upstream.getBody();
        if (body != null && body.length > 0) {
            response.getOutputStream().write(body);
        }
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(
                "{\"status\":\"error\",\"message\":\"" + message + "\",\"data\":null}"
        );
    }

    private String resolveTarget(String path) {
        if (path.startsWith("/api/v1/auth/") || path.startsWith("/api/v1/users/")) {
            return authUrl;
        }
        if (path.startsWith("/api/v1/payments")) {
            return paymentUrl;
        }
        if (path.startsWith("/api/v1/")) {
            return warehouseUrl;
        }
        return null;
    }
}
