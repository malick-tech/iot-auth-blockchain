package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {

    Optional<Device> findBySerialNumber(String serialNumber);

    Optional<Device> findByDid(String did);

    boolean existsBySerialNumber(String serialNumber);

    boolean existsByMacAddress(String macAddress);

    boolean existsByDid(String did);

    boolean existsByPublicKey(String publicKey);

    List<Device> findByStatus(DeviceStatus status);

    List<Device> findByLogicalGroup(String logicalGroup);

    List<Device> findByLocation(String location);

    List<Device> findByResponsible(String responsible);
}
