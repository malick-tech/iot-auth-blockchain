package com.iotauth.iot_auth.exception;

/** Quota de requêtes dépassé pour un identifiant donné (DID, IP...). Traduit en HTTP 429. */
public class RateLimitExceededException extends RuntimeException {

    public RateLimitExceededException(String message) {
        super(message);
    }
}
