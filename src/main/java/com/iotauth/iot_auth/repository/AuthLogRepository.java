package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.AuthLog;
import com.iotauth.iot_auth.domain.enums.EventType;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthLogRepository extends JpaRepository<AuthLog, Long> {

    List<AuthLog> findByDeviceIdOrderByCreatedAtDesc(String deviceId);

    List<AuthLog> findByDeviceIdAndSuccessFalseAndCreatedAtAfter(String deviceId, Instant since);

    List<AuthLog> findByEventTypeAndCreatedAtAfter(EventType eventType, Instant since);

    long countByDeviceIdAndSuccessFalseAndCreatedAtAfter(String deviceId, Instant since);
}
