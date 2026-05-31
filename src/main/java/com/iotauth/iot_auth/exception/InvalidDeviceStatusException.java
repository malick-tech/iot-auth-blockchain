package com.iotauth.iot_auth.exception;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;

public class InvalidDeviceStatusException extends RuntimeException {

    public InvalidDeviceStatusException(String message) {
        super(message);
    }

    public static InvalidDeviceStatusException expected(DeviceStatus expected, DeviceStatus actual) {
        return new InvalidDeviceStatusException(
                "Statut invalide : " + actual + " (statut attendu : " + expected + ")"
        );
    }
}
