package com.iotauth.iot_auth.exception;

public class DeviceSuspendedException extends RuntimeException {

    public DeviceSuspendedException(String message) {
        super(message);
    }

    public static DeviceSuspendedException byDid(String did) {
        return new DeviceSuspendedException("Le dispositif est suspendu : " + did);
    }
}
