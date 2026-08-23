package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.AuthLog;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.repository.AuthLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuthLogRepository authLogRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuthLog record(
            EventType eventType,
            String deviceDid,
            ActorType actor,
            boolean success,
            String details
    ) {
        return record(eventType, deviceDid, actor, success, details, null, null);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
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
        if (actor == ActorType.ADMIN) {
            log.setAdminUsername(CurrentAdminHolder.get());
        }
        return authLogRepository.save(log);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuthLog recordAdminAction(
            EventType eventType,
            String adminUsername,
            boolean success,
            String details
    ) {
        AuthLog log = new AuthLog();
        log.setEventType(eventType);
        log.setActor(ActorType.ADMIN);
        log.setAdminUsername(adminUsername);
        log.setSuccess(success);
        log.setDetails(details);
        return authLogRepository.save(log);
    }

    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public org.springframework.data.domain.Page<com.iotauth.iot_auth.dto.response.AuthLogResponse> search(
            com.iotauth.iot_auth.domain.enums.EventType eventType,
            String deviceDid,
            String adminUsername,
            Boolean success,
            int page,
            int size
    ) {
        org.springframework.data.jpa.domain.Specification<com.iotauth.iot_auth.domain.entity.AuthLog> spec =
                (root, query, cb) -> cb.conjunction();

        if (eventType != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("eventType"), eventType));
        }
        if (deviceDid != null && !deviceDid.isBlank()) {
            // Bug 11 fix : échappement des caractères spéciaux LIKE (% et _)
            // pour éviter qu'un filtre "did:algo:%" ne retourne tous les devices.
            final String escapedDid = escapeLike(deviceDid);
            spec = spec.and((root, query, cb) -> cb.like(root.get("deviceDid"), "%" + escapedDid + "%"));
        }
        if (adminUsername != null && !adminUsername.isBlank()) {
            final String escapedAdmin = escapeLike(adminUsername);
            spec = spec.and((root, query, cb) -> cb.like(
                    cb.lower(root.get("adminUsername")),
                    "%" + escapedAdmin.toLowerCase() + "%"
            ));
        }
        if (success != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("success"), success));
        }

        org.springframework.data.domain.Pageable pageable = org.springframework.data.domain.PageRequest.of(
                page, size,
                org.springframework.data.domain.Sort.by("timestamp").descending()
        );

        return authLogRepository.findAll(spec, pageable)
                .map(log -> com.iotauth.iot_auth.dto.response.AuthLogResponse.builder()
                        .id(log.getId())
                        .deviceDid(log.getDeviceDid())
                        .eventType(log.getEventType().name())
                        .actor(log.getActor() != null ? log.getActor().name() : null)
                        .adminUsername(log.getAdminUsername())
                        .success(log.getSuccess())
                        .sourceIp(log.getSourceIp())
                        .details(log.getDetails())
                        .metadata(log.getMetadata())
                        .timestamp(log.getTimestamp())
                        .build());
    }

    /**
     * Échappe les caractères spéciaux SQL LIKE (% et _) pour qu'ils soient
     * traités comme des littéraux et non comme des wildcards.
     */
    private String escapeLike(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }
}
