package com.grainflow.gateway;

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

    private static final Set<String> SKIP_HEADERS = Set.of(
            "host", "content-length", "transfer-encoding"
    );

    private final RestClient restClient;

    @Value("${services.auth.url}")
    private String authUrl;

    @Value("${services.warehouse.url}")
    private String warehouseUrl;

    public ProxyFilter() {
        this.restClient = RestClient.create();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String targetBase = resolveTarget(path);

        if (targetBase == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String query = request.getQueryString();
        String targetUrl = targetBase + path + (query != null ? "?" + query : "");
        String method = request.getMethod();

        log.debug("[PROXY] {} {} → {}", method, path, targetUrl);

        byte[] requestBody = request.getInputStream().readAllBytes();

        try {
            ResponseEntity<byte[]> upstream = restClient
                    .method(HttpMethod.valueOf(method))
                    .uri(targetUrl)
                    .headers(h -> Collections.list(request.getHeaderNames())
                            .stream()
                            .filter(name -> !SKIP_HEADERS.contains(name.toLowerCase()))
                            .forEach(name -> h.add(name, request.getHeader(name))))
                    .body(requestBody)
                    .exchange((req, res) -> {
                        byte[] body = res.getBody().readAllBytes();
                        return ResponseEntity.status(res.getStatusCode())
                                .headers(res.getHeaders())
                                .body(body);
                    });

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

        } catch (Exception e) {
            log.error("[PROXY] {} {} → {} FAILED: {}", method, path, targetUrl, e.getMessage());
            response.setStatus(502);
            response.getWriter().write("{\"error\":\"Bad Gateway\"}");
        }
    }

    private String resolveTarget(String path) {
        if (path.startsWith("/api/v1/auth/") || path.startsWith("/api/v1/users/")) {
            return authUrl;
        }
        if (path.startsWith("/api/v1/")) {
            return warehouseUrl;
        }
        return null;
    }
}
