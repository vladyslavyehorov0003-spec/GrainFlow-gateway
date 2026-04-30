package com.grainflow.gateway.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

// Calls auth-service /validate to verify the token and retrieve user context.
// Warehouse does not know anything about JWT internals — auth-service is the single source of truth.
@Slf4j
@Component
public class AuthClient {

    private final RestClient restClient;

    public AuthClient(@Value("${services.auth.url}") String authServiceUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(authServiceUrl)
                .build();
    }

    // Returns ValidateResponse from auth-service.
    // Returns valid=false on any network or parsing error — treated as unauthenticated.
    public ValidateResponse validate(String bearerToken) {
        try {
            // auth-service wraps the response in ApiResponse<ValidateTokenResponse>,
            // but we only need the data field — use a wrapper to unwrap it
            AuthApiResponse response = restClient.get()
                    .uri("/api/v1/auth/validate")
                    .header("Authorization", bearerToken)
                    .retrieve()
                    .body(AuthApiResponse.class);

            if (response == null || response.data() == null) {
                return invalid();
            }


            return response.data();
        } catch (RestClientException e) {
            log.error("Failed to reach auth-service for token validation: {}", e.getMessage());
            return invalid();
        }
    }

    private ValidateResponse invalid() {
        return new ValidateResponse(false, null, null, null, null,null,false);
    }

    // Unwraps ApiResponse<ValidateTokenResponse> returned by auth-service
    private record AuthApiResponse(String status, String message, ValidateResponse data) {}
}
