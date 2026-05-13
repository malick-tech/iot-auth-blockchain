package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

    public interface DeviceRepository extends JpaRepository<Device, Long> {

        Optional<Device> findByDeviceId(String deviceId);

        Optional<Device> findByDid(String did);

        boolean existsByDeviceId(String deviceId);

        boolean existsByDid(String did);

        List<Device> findByStatus(DeviceStatus status);
    }