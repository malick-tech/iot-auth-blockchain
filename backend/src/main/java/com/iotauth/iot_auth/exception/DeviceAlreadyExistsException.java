package com.iotauth.iot_auth.exception;

public class DeviceAlreadyExistsException extends RuntimeException {

    public DeviceAlreadyExistsException(String message) {
        super(message);
    }

    public static DeviceAlreadyExistsException bySerial(String serialNumber) {
        return new DeviceAlreadyExistsException("Un dispositif existe déjà avec le numéro de série : " + serialNumber);
    }

    public static DeviceAlreadyExistsException byDid(String did) {
        return new DeviceAlreadyExistsException("Un dispositif existe déjà avec le DID : " + did);
    }
}
