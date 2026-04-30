package com.grainflow.gateway.security;

import java.util.UUID;

// Maps the response from auth-service GET /api/v1/auth/validate
public record ValidateResponse(
        boolean valid,
        UUID userId,
        UUID companyId,
        String email,
        String role,
        String subscriptionStatus,
        boolean companyVerified
) {}
