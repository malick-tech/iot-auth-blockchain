package com.iotauth.iot_auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class OperationalVerifyResponse {
    private boolean authorized;
    private String did;
    private String status;
    private List<String> permissions;
    private String reason;
    private Map<String, Object> metrics;
}