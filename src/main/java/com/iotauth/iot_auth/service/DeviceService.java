package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.request.DeviceRegisterRequest;
import com.iotauth.iot_auth.dto.response.DeviceResponse;
import com.iotauth.iot_auth.exception.DeviceAlreadyExistsException;
import com.iotauth.iot_auth.exception.DeviceNotFoundException;
import com.iotauth.iot_auth.repository.DeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DeviceService {

    private final DeviceRepository deviceRepository;
    private final AuditLogService auditLogService;

    @Transactional
    public DeviceResponse preRegisterDevice(DeviceRegisterRequest request) {
        ensureDeviceIsUnique(request);

        Device device = new Device();
        device.setSerialNumber(request.getSerialNumber());
        device.setMacAddress(request.getMacAddress());
        device.setDeviceType(request.getDeviceType());
        device.setLocation(request.getLocation());
        device.setLogicalGroup(request.getLogicalGroup());
        device.setResponsible(request.getResponsible());
        device.setStatus(DeviceStatus.PENDING);

        Device savedDevice = deviceRepository.save(device);
        auditLogService.record(
                EventType.DEVICE_PRE_REGISTERED,
                null,
                ActorType.ADMIN,
                true,
                "Pré-enregistrement du dispositif " + savedDevice.getSerialNumber()
        );

        return toResponse(savedDevice);
    }

    @Transactional(readOnly = true)
    public List<DeviceResponse> getAllDevices() {
        return deviceRepository.findAll()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public DeviceResponse getDeviceById(Long id) {
        return toResponse(deviceRepository.findById(id)
                .orElseThrow(() -> DeviceNotFoundException.byId(id)));
    }

    @Transactional(readOnly = true)
    public DeviceResponse getDeviceByDid(String did) {
        return toResponse(deviceRepository.findByDid(did)
                .orElseThrow(() -> DeviceNotFoundException.byDid(did)));
    }

    @Transactional(readOnly = true)
    public List<DeviceResponse> getDevicesByStatus(DeviceStatus status) {
        return deviceRepository.findByStatus(status)
                .stream()
                .map(this::toResponse)
                .toList();
    }

    private void ensureDeviceIsUnique(DeviceRegisterRequest request) {
        if (deviceRepository.existsBySerialNumber(request.getSerialNumber())) {
            throw DeviceAlreadyExistsException.bySerial(request.getSerialNumber());
        }
        if (StringUtils.hasText(request.getMacAddress())
                && deviceRepository.existsByMacAddress(request.getMacAddress())) {
            throw new DeviceAlreadyExistsException(
                    "Un dispositif existe déjà avec l'adresse MAC : " + request.getMacAddress()
            );
        }
    }

    private DeviceResponse toResponse(Device device) {
        return DeviceResponse.builder()
                .id(device.getId())
                .serialNumber(device.getSerialNumber())
                .macAddress(device.getMacAddress())
                .did(device.getDid())
                .publicKey(device.getPublicKey())
                .status(device.getStatus())
                .algorandTxId(device.getAlgorandTxId())
                .deviceType(device.getDeviceType())
                .location(device.getLocation())
                .logicalGroup(device.getLogicalGroup())
                .responsible(device.getResponsible())
                .activatedAt(device.getActivatedAt())
                .suspendedAt(device.getSuspendedAt())
                .revokedAt(device.getRevokedAt())
                .lastSeenAt(device.getLastSeenAt())
                .createdAt(device.getCreatedAt())
                .updatedAt(device.getUpdatedAt())
                .build();
    }
}
