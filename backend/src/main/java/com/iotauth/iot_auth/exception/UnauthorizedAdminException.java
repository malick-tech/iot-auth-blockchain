package com.iotauth.iot_auth.exception;

public class UnauthorizedAdminException extends RuntimeException {
    public UnauthorizedAdminException(String message) {
        super(message);
    }
}