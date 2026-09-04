package com.iotauth.iot_auth.domain.enums;

/**
 * Catégories de compteurs d'anomalies stockés dans Redis.
 * Utilisées par AnomalyDetectionService, RevocationService et
 * DeviceInactivityMonitorService pour identifier les fenêtres
 * de détection lors des opérations incrementFailures/resetFailures.
 */
public final class FailureCategory {

    /** Echecs de protocole challenge-response lors de l'enrôlement ou du renouvellement JWT. */
    public static final String CHALLENGE = "challenge";

    /** Echecs de vérification de Verifiable Presentation (signature VP invalide). */
    public static final String VP = "vp";

    /** Violations de permissions (permission demandée non accordée dans le VC). */
    public static final String PERMISSION = "perm";

    private FailureCategory() {
        // Classe utilitaire, pas d'instanciation
    }
}
