package com.iotauth.iot_auth.exception;

public class NonceExpiredException extends RuntimeException {

    public NonceExpiredException(String identifier) {
        super("Nonce expired or not found for: " + identifier);
    }
}
