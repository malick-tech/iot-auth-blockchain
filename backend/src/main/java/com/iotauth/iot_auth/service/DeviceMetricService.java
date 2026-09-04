package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.DeviceMetric;
import com.iotauth.iot_auth.dto.response.DeviceMetricResponse;
import com.iotauth.iot_auth.repository.DeviceMetricRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

/**
 * Persiste les métriques opérationnelles des dispositifs IoT et expose
 * un accès paginé à l'historique pour la console d'administration.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceMetricService {

    private final DeviceMetricRepository metricRepository;

    /**
     * Enregistre les métriques reçues d'un dispositif après une vérification
     * JWT PoP réussie. Les champs inconnus sont ignorés silencieusement.
     *
     * @param deviceDid DID du dispositif (déjà validé en amont)
     * @param metrics   map de métriques libre issue du payload MQTT
     */
    @Transactional
    public void saveMetrics(String deviceDid, Map<String, Object> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return;
        }

        try {
            DeviceMetric metric = DeviceMetric.builder()
                    .deviceDid(deviceDid)
                    .temperatureC(toDouble(metrics.get("temperatureC")))
                    .humidityPercent(toDouble(metrics.get("humidityPercent")))
                    .batteryPercent(toDouble(metrics.get("batteryPercent")))
                    .uptimeSeconds(toLong(metrics.get("uptimeSeconds")))
                    .measuredAt(toInstant(metrics.get("measuredAt")))
                    .receivedAt(Instant.now())
                    .build();

            metricRepository.save(metric);
            log.debug("Métriques persistées pour did={}", deviceDid);
        } catch (Exception e) {
            // La persistance des métriques ne doit jamais bloquer la réponse
            // opérationnelle — on logue et on continue.
            log.warn("Erreur lors de la persistance des métriques pour did={} : {}", deviceDid, e.getMessage());
        }
    }

    /**
     * Retourne l'historique paginé des métriques d'un dispositif,
     * du plus récent au plus ancien.
     */
    @Transactional(readOnly = true)
    public Page<DeviceMetricResponse> getMetrics(String deviceDid, Pageable pageable) {
        return metricRepository
                .findByDeviceDidOrderByMeasuredAtDesc(deviceDid, pageable)
                .map(this::toResponse);
    }

    /**
     * Retourne les métriques d'un dispositif dans une fenêtre temporelle.
     *
     * @param deviceDid DID du dispositif
     * @param from      début de la fenêtre (inclusive)
     * @param to        fin de la fenêtre (inclusive)
     * @param pageable  pagination et tri
     */
    @Transactional(readOnly = true)
    public Page<DeviceMetricResponse> getMetricsInRange(
            String deviceDid, Instant from, Instant to, Pageable pageable
    ) {
        return metricRepository
                .findByDeviceDidAndMeasuredAtBetweenOrderByMeasuredAtDesc(deviceDid, from, to, pageable)
                .map(this::toResponse);
    }

    private DeviceMetricResponse toResponse(DeviceMetric m) {
        return DeviceMetricResponse.builder()
                .id(m.getId())
                .deviceDid(m.getDeviceDid())
                .temperatureC(m.getTemperatureC())
                .humidityPercent(m.getHumidityPercent())
                .batteryPercent(m.getBatteryPercent())
                .uptimeSeconds(m.getUptimeSeconds())
                .measuredAt(m.getMeasuredAt())
                .receivedAt(m.getReceivedAt())
                .build();
    }

    // ── helpers de conversion ────────────────────────────────────────────────

    private Double toDouble(Object value) {
        if (value == null) return null;
        if (value instanceof Number n) return n.doubleValue();
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Long toLong(Object value) {
        if (value == null) return null;
        if (value instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Instant toInstant(Object value) {
        if (value == null) return null;
        if (value instanceof Number n) return Instant.ofEpochSecond(n.longValue());
        try {
            return Instant.ofEpochSecond(Long.parseLong(value.toString()));
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
