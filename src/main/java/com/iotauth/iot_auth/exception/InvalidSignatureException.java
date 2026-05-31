package com.iotauth.iot_auth.exception;

public class InvalidSignatureException extends RuntimeException {

    public InvalidSignatureException() {
        super();
    }

    public InvalidSignatureException(String message) {
        super(message);
    }

    public InvalidSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
