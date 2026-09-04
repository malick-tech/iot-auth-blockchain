package com.iotauth.iot_auth.domain.enums;

/**
 * Préfixes utilisés pour lire les boxes Algorand (méthode did:algo app namespace).
 * Utilisés par AlgorandService.readBox(), OperationalVerificationService,
 * AuthenticationService et AlgorandPublishingRecoveryService.
 */
public final class AlgorandBoxPrefix {

    /** Lit le statut du DID depuis la metadata box (retourne "ACTIVE" ou "REVOKED"). */
    public static final String STATUS = "st:";

    /** Lit le DID Document JSON depuis la data box. */
    public static final String DOCUMENT = "doc:";

    private AlgorandBoxPrefix() {
        // Classe utilitaire, pas d'instanciation
    }
}
