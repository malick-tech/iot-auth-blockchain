package com.iotauth.iot_auth.exception;

public class NonceExpiredException extends RuntimeException {

    public NonceExpiredException() {
        super("Le nonce est expiré ou introuvable");
    }

    public NonceExpiredException(String did) {
        super("Le nonce est expiré ou introuvable pour le DID : " + did);
    }
}
