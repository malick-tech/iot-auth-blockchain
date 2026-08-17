package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.AuthLog;
import com.iotauth.iot_auth.domain.enums.ActorType;
import com.iotauth.iot_auth.domain.enums.EventType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuthLogRepository extends JpaRepository<AuthLog, Long>,
        org.springframework.data.jpa.repository.JpaSpecificationExecutor<AuthLog> {

    List<AuthLog> findByDeviceDid(String deviceDid);

    List<AuthLog> findByEventType(EventType eventType);

    List<AuthLog> findByActor(ActorType actor);

    List<AuthLog> findBySuccess(Boolean success);

    List<AuthLog> findByDeviceDidAndEventType(String deviceDid, EventType eventType);

    List<AuthLog> findByDeviceDidAndTimestampBetween(
            String deviceDid,
            LocalDateTime start,
            LocalDateTime end
    );

    List<AuthLog> findByTimestampBetween(LocalDateTime start, LocalDateTime end);
}
