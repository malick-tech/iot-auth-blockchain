package com.iotauth.iot_auth.controller.admin;

import com.iotauth.iot_auth.domain.enums.EventType;
import com.iotauth.iot_auth.dto.response.AuthLogResponse;
import com.iotauth.iot_auth.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/admin/logs")
@RequiredArgsConstructor
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
   public Page<AuthLogResponse> search(
            @RequestParam(name = "eventType", required = false) EventType eventType,
            @RequestParam(name = "did", required = false) String did,
            @RequestParam(name = "adminUsername", required = false) String adminUsername,
            @RequestParam(name = "success", required = false) Boolean success,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size
    ) {
        return auditLogService.search(eventType, did, adminUsername, success, page, size);
    }
}
