package com.iotauth.iot_auth.exception;

public class DeviceRevokedException extends RuntimeException {

    public DeviceRevokedException(String message) {
        super(message);
    }

    public static DeviceRevokedException byDid(String did) {
        return new DeviceRevokedException("Le dispositif est révoqué : " + did);
    }
}
