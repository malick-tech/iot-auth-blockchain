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

@RestController
@RequestMapping(path = "/api/admin/devices/{did}", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class RevocationController {

    private final RevocationService revocationService;

    @PatchMapping(path = "/suspend", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse suspendDevice(
            @PathVariable String did,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.suspendDevice(did, request);
    }

    @PatchMapping(path = "/reactivate")
    public DeviceStatusResponse reactivateDevice(@PathVariable String did) {
        return revocationService.reactivateDevice(did);
    }

    @PatchMapping(path = "/revoke", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeviceStatusResponse revokeDevice(
            @PathVariable String did,
            @Valid @RequestBody RevocationRequest request
    ) {
        return revocationService.revokeDevice(did, request);
    }

    @GetMapping(path = "/status")
    public DeviceStatusResponse getDeviceStatus(@PathVariable String did) {
        return revocationService.getDeviceStatus(did);
    }
}
