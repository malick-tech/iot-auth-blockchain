package com.iotauth.iot_auth.exception;

public class InvalidAdminCredentialsException extends RuntimeException {
    public InvalidAdminCredentialsException() {
        super("Identifiants administrateur invalides");
    }
}