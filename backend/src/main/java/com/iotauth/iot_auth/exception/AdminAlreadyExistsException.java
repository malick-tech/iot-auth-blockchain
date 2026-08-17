package com.iotauth.iot_auth.exception;

public class AdminAlreadyExistsException extends RuntimeException {
    public AdminAlreadyExistsException(String username) {
        super("Un compte admin existe déjà avec le nom d'utilisateur : " + username);
    }
}