package com.iotauth.iot_auth.exception;

public class DeviceNotFoundException extends RuntimeException {

    public DeviceNotFoundException(String message) {
        super(message);
    }

    public static DeviceNotFoundException bySerial(String serialNumber) {
        return new DeviceNotFoundException("Aucun dispositif trouvé pour le numéro de série : " + serialNumber);
    }

    public static DeviceNotFoundException byDid(String did) {
        return new DeviceNotFoundException("Aucun dispositif trouvé pour le DID : " + did);
    }

    public static DeviceNotFoundException byId(Long id) {
        return new DeviceNotFoundException("Aucun dispositif trouvé pour l'identifiant : " + id);
    }
}
