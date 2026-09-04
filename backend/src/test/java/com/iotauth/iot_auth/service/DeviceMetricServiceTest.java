package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.domain.entity.DeviceMetric;
import com.iotauth.iot_auth.repository.DeviceMetricRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeviceMetricServiceTest {

    @Mock
    private DeviceMetricRepository metricRepository;

    private DeviceMetricService service;

    private static final String DID = "did:algo:DEVICE";

    @BeforeEach
    void setUp() {
        service = new DeviceMetricService(metricRepository);
    }

    @Test
    void saveMetrics_withFullPayload_shouldPersistAllFields() {
        when(metricRepository.save(any(DeviceMetric.class)))
                .thenAnswer(i -> i.getArgument(0));

        Map<String, Object> metrics = Map.of(
                "temperatureC", 22.5,
                "humidityPercent", 55.0,
                "batteryPercent", 87.0,
                "uptimeSeconds", 3600L,
                "measuredAt", 1700000000L
        );

        service.saveMetrics(DID, metrics);

        ArgumentCaptor<DeviceMetric> captor = ArgumentCaptor.forClass(DeviceMetric.class);
        verify(metricRepository).save(captor.capture());
        DeviceMetric saved = captor.getValue();

        assertThat(saved.getDeviceDid()).isEqualTo(DID);
        assertThat(saved.getTemperatureC()).isEqualTo(22.5);
        assertThat(saved.getHumidityPercent()).isEqualTo(55.0);
        assertThat(saved.getBatteryPercent()).isEqualTo(87.0);
        assertThat(saved.getUptimeSeconds()).isEqualTo(3600L);
        assertThat(saved.getMeasuredAt().getEpochSecond()).isEqualTo(1700000000L);
        assertThat(saved.getReceivedAt()).isNotNull();
    }

    @Test
    void saveMetrics_withPartialPayload_shouldPersistKnownFieldsAndNullRest() {
        when(metricRepository.save(any(DeviceMetric.class)))
                .thenAnswer(i -> i.getArgument(0));

        Map<String, Object> metrics = Map.of("temperatureC", 19.3);

        service.saveMetrics(DID, metrics);

        ArgumentCaptor<DeviceMetric> captor = ArgumentCaptor.forClass(DeviceMetric.class);
        verify(metricRepository).save(captor.capture());
        DeviceMetric saved = captor.getValue();

        assertThat(saved.getTemperatureC()).isEqualTo(19.3);
        assertThat(saved.getHumidityPercent()).isNull();
        assertThat(saved.getBatteryPercent()).isNull();
        assertThat(saved.getUptimeSeconds()).isNull();
        assertThat(saved.getMeasuredAt()).isNull();
    }

    @Test
    void saveMetrics_withNullMap_shouldNotPersist() {
        service.saveMetrics(DID, null);
        verify(metricRepository, never()).save(any());
    }

    @Test
    void saveMetrics_withEmptyMap_shouldNotPersist() {
        service.saveMetrics(DID, Map.of());
        verify(metricRepository, never()).save(any());
    }

    @Test
    void saveMetrics_whenRepositoryThrows_shouldNotPropagateException() {
        when(metricRepository.save(any())).thenThrow(new RuntimeException("DB down"));

        assertThatCode(() -> service.saveMetrics(DID, Map.of("temperatureC", 21.0)))
                .doesNotThrowAnyException();
    }

    @Test
    void saveMetrics_withIntegerValues_shouldConvertToDouble() {
        when(metricRepository.save(any(DeviceMetric.class)))
                .thenAnswer(i -> i.getArgument(0));

        // Jackson peut désérialiser des nombres entiers en Integer, pas en Double
        Map<String, Object> metrics = Map.of(
                "temperatureC", 22,
                "batteryPercent", 100
        );

        service.saveMetrics(DID, metrics);

        ArgumentCaptor<DeviceMetric> captor = ArgumentCaptor.forClass(DeviceMetric.class);
        verify(metricRepository).save(captor.capture());

        assertThat(captor.getValue().getTemperatureC()).isEqualTo(22.0);
        assertThat(captor.getValue().getBatteryPercent()).isEqualTo(100.0);
    }
}
