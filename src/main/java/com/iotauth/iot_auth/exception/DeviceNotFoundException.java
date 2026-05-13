package com.iotauth.iot_auth.exception;

public class DeviceNotFoundException extends RuntimeException {

    public DeviceNotFoundException(String message) {
        super(message);
    }

    public static DeviceNotFoundException byDeviceId(String deviceId) {
        return new DeviceNotFoundException("Device not found: " + deviceId);
    }

    public static DeviceNotFoundException byDid(String did) {
        return new DeviceNotFoundException("Device not found for DID: " + did);
    }
}
