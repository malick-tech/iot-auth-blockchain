package com.iotauth.iot_auth.controller.admin;

import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.dto.request.DeviceRegisterRequest;
import com.iotauth.iot_auth.dto.response.DeviceResponse;
import com.iotauth.iot_auth.service.DeviceService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

import java.util.List;

@RestController
@RequestMapping(path = "/api/admin/devices", produces = MediaType.APPLICATION_JSON_VALUE)
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
public class DeviceAdminController {

    private final DeviceService deviceService;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public DeviceResponse preRegisterDevice(@Valid @RequestBody DeviceRegisterRequest request) {
        return deviceService.preRegisterDevice(request);
    }

    @GetMapping
        public List<DeviceResponse> getAllDevices(@RequestParam(name = "status", required = false) DeviceStatus status) {        if (status != null) {
            return deviceService.getDevicesByStatus(status);
        }
        return deviceService.getAllDevices();
    }

    @GetMapping(path = "/{id}")
    public DeviceResponse getDeviceById(@PathVariable Long id) {
        return deviceService.getDeviceById(id);
    }

    @GetMapping(path = "/serial/{serialNumber}")
    public DeviceResponse getDeviceBySerialNumber(@PathVariable String serialNumber) {
        return deviceService.getDeviceBySerialNumber(serialNumber);
    }

    @GetMapping(path = "/did/{did}")
    public DeviceResponse getDeviceByDid(@PathVariable String did) {
        return deviceService.getDeviceByDid(did);
    }
}
