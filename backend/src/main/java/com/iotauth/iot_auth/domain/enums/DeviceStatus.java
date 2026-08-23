package com.iotauth.iot_auth.domain.enums;

public enum DeviceStatus {
    PENDING,
    PRE_REGISTERED,
    /**
     * Statut transitoire : la publication du DID sur Algorand est en cours.
     * Un device qui reste dans cet état après un redémarrage indique une
     * corruption partielle (Algorand OK mais commit PostgreSQL échoué).
     * L'admin peut le réactiver manuellement via l'API de gestion.
     */
    PUBLISHING,
    ACTIVE,
    SUSPENDED,
    REVOKED
}
