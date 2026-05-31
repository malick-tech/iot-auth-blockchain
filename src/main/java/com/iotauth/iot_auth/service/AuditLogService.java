package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.AuthLog;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.repository.AuthLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuthLogRepository authLogRepository;

    public AuthLog record(
            EventType eventType,
            String deviceDid,
            ActorType actor,
            boolean success,
            String details
    ) {
        return record(eventType, deviceDid, actor, success, details, null, null);
    }

    public AuthLog record(
            EventType eventType,
            String deviceDid,
            ActorType actor,
            boolean success,
            String details,
            String metadata,
            String sourceIp
    ) {
        AuthLog log = new AuthLog();
        log.setEventType(eventType);
        log.setDeviceDid(deviceDid);
        log.setActor(actor);
        log.setSuccess(success);
        log.setDetails(details);
        log.setMetadata(metadata);
        log.setSourceIp(sourceIp);
        return authLogRepository.save(log);
    }
}
