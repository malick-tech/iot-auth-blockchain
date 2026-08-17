package com.iotauth.iot_auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class AuthLogResponse {
    private Long id;
    private String deviceDid;
    private String eventType;
    private String actor;
    private String adminUsername;
    private Boolean success;
    private String sourceIp;
    private String details;
    private String metadata;
    private LocalDateTime timestamp;
}
