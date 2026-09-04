package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.DeviceMetric;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface DeviceMetricRepository extends JpaRepository<DeviceMetric, Long> {

    /** Historique paginé d'un dispositif, du plus récent au plus ancien. */
    Page<DeviceMetric> findByDeviceDidOrderByMeasuredAtDesc(String deviceDid, Pageable pageable);

    /** Métriques d'un dispositif dans une fenêtre temporelle (pour graphes). */
    Page<DeviceMetric> findByDeviceDidAndMeasuredAtBetweenOrderByMeasuredAtDesc(
            String deviceDid, Instant from, Instant to, Pageable pageable
    );

    /** Nombre total de mesures pour un dispositif. */
    long countByDeviceDid(String deviceDid);
}
