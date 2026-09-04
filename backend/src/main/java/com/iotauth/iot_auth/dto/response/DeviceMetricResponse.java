package com.iotauth.iot_auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * Représentation lisible d'une mesure IoT pour les endpoints admin.
 */
@Data
@Builder
public class DeviceMetricResponse {
    private Long id;
    private String deviceDid;
    private Double temperatureC;
    private Double humidityPercent;
    private Double batteryPercent;
    private Long uptimeSeconds;
    private Instant measuredAt;
    private Instant receivedAt;
}
