package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CacheHitLogRequest {

    @NotBlank
    private String did;

    private boolean authorized;

    private String reason;

    private String requestedPermission;

    /**
     * Catégorie de refus, définie explicitement par la Gateway (pas déduite
     * d'un texte libre côté backend). Seule la valeur "PERMISSION_VIOLATION"
     * déclenche actuellement la suspension automatique (Déclencheur 3).
     */
    private String violationType;
}