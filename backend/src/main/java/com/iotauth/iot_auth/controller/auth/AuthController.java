package com.iotauth.iot_auth.controller.auth;

import com.iotauth.iot_auth.dto.request.VPRequest;
import com.iotauth.iot_auth.dto.response.ApiResponse;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping(path = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    /**
     * Authenticates a device by verifying its Verifiable Presentation (VP).
     * The VP contains the device's Verifiable Credential (VC) along with a proof of possession.
     *
     * Request flow:
     * 1. Device sends VP with signed VC + proof
     * 2. Backend validates VC signature and expiration
     * 3. Backend verifies device status (not suspended/revoked)
     * 4. Backend performs anomaly detection
     * 5. Backend emits JWT PoP (Proof of Possession token)
     *
     * @param request VPRequest containing:
     *                - did: device identifier
     *                - verifiablePresentation: signed credential
     *                - challenge: nonce from backend
     *                - signature: signature proving key possession
     * @return JwtPopResponse with JWT PoP token and permissions
     */

    /**
     * Ã‰met un nonce de fraÃ®cheur (challenge) pour le renouvellement du JWT PoP.
     * Le dispositif doit appeler cet endpoint AVANT /authenticate, signer
     * (challenge || VP) avec sa clÃ© privÃ©e, puis soumettre le rÃ©sultat.
     *
     * @param did DID du dispositif (dÃ©jÃ  enrÃ´lÃ©, statut ACTIVE)
     * @return ChallengeResponse contenant le nonce et son TTL
     */
    @PostMapping(path = "/challenge/{did}")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<ChallengeResponse> requestChallenge(@PathVariable String did) {
        log.info("Challenge de renouvellement demandÃ© pour DID: {}", did);
        ChallengeResponse response = authenticationService.issueRenewalChallenge(did);
        return ResponseEntity.ok(response);
    }

    @PostMapping(path = "/authenticate", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<JwtPopResponse> authenticate(
            @Valid @RequestBody VPRequest request
    ) {
        log.info("Authentication request received for DID: {}", request.getDid());
        try {
            JwtPopResponse response = authenticationService.authenticateDevice(request);
            log.info("Authentication successful for DID: {}", request.getDid());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Authentication failed for DID: {} - Error: {}", request.getDid(), e.getMessage());
            throw e;
        }
    }

    /**
     * Health check endpoint for monitoring.
     * Useful for Docker health checks and load balancer probes.
     *
     * @return ApiResponse with status
     */
    @PostMapping(path = "/health")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<ApiResponse> health() {
        log.debug("Health check endpoint called");
        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message("Authentication service is healthy")
                        .build()
        );
    }
}
