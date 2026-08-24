package com.iotauth.iot_auth.controller.admin;

import com.iotauth.iot_auth.dto.request.RevocationRequest;
import com.iotauth.iot_auth.dto.response.DeviceStatusResponse;
import com.iotauth.iot_auth.service.RevocationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

@RestController
@RequestMapping(path = "/api/admin/devices", produces = MediaType.APPLICATION_JSON_VALUE)
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
public class RevocationController {

    private final RevocationService revocationService;

    @PatchMapping(path = "/{did}/suspend", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse suspendDevice(
            @PathVariable String did,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.suspendDevice(did, request);
    }

    @PatchMapping(path = "/{did}/reactivate")
    public DeviceStatusResponse reactivateDevice(@PathVariable String did) {
        return revocationService.reactivateDevice(did);
    }

    @PatchMapping(path = "/{did}/revoke", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse revokeDevice(
            @PathVariable String did,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.revokeDevice(did, request);
    }

    @GetMapping(path = "/{did}/status")
    public DeviceStatusResponse getDeviceStatus(@PathVariable String did) {
        return revocationService.getDeviceStatus(did);
    }

    @PatchMapping(path = "/serial/{serialNumber}/suspend", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse suspendDeviceBySerialNumber(
            @PathVariable String serialNumber,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.suspendDeviceBySerialNumber(serialNumber, request);
    }

    @PatchMapping(path = "/serial/{serialNumber}/reactivate")
    public DeviceStatusResponse reactivateDeviceBySerialNumber(@PathVariable String serialNumber) {
        return revocationService.reactivateDeviceBySerialNumber(serialNumber);
    }

    @PatchMapping(path = "/serial/{serialNumber}/revoke", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse revokeDeviceBySerialNumber(
            @PathVariable String serialNumber,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.revokeDeviceBySerialNumber(serialNumber, request);
    }

    @GetMapping(path = "/serial/{serialNumber}/status")
    public DeviceStatusResponse getDeviceStatusBySerialNumber(@PathVariable String serialNumber) {
        return revocationService.getDeviceStatusBySerialNumber(serialNumber);
    }
}
