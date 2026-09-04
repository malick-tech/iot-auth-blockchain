package com.iotauth.iot_auth.controller.operational;

import com.iotauth.iot_auth.dto.request.CacheHitLogRequest;
import com.iotauth.iot_auth.dto.request.OperationalVerifyRequest;
import com.iotauth.iot_auth.dto.response.OperationalVerifyResponse;
import com.iotauth.iot_auth.service.OperationalVerificationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/operational", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class OperationalController {

    private final OperationalVerificationService operationalVerificationService;

    @PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public OperationalVerifyResponse verify(@Valid @RequestBody OperationalVerifyRequest request) {
        return operationalVerificationService.verify(request);
    }

    /**
     * Endpoint "fire-and-forget" appelé par la Gateway après chaque décision
     * prise localement (cache HIT), uniquement pour alimenter le journal
     * d'audit centralisé — aucune revérification cryptographique ici.
     */
    @PostMapping(path = "/log-cache-hit", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void logCacheHit(@Valid @RequestBody CacheHitLogRequest request) {
        operationalVerificationService.logCacheHitDecision(request);
    }
}