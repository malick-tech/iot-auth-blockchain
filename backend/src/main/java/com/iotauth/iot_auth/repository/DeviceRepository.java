package com.iotauth.iot_auth.repository;

import com.iotauth.iot_auth.domain.entity.Device;
import com.iotauth.iot_auth.domain.enums.DeviceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
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

    /**
     * Bug 5 fix : inclut les devices ACTIVE dont lastSeenAt est NULL.
     * Un device activé mais qui n'a jamais envoyé de signal (lastSeenAt null)
     * est considéré inactif depuis son activation et doit être suspendu.
     * La méthode dérivée JPA standard exclut les NULL (SQL: lastSeenAt < cutoff),
     * d'où l'utilisation d'une requête JPQL explicite avec IS NULL OR <.
     */
    @Query("SELECT d FROM Device d WHERE d.status = :status AND (d.lastSeenAt IS NULL OR d.lastSeenAt < :cutoff)")
    List<Device> findByStatusAndLastSeenAtBeforeOrNull(
            @Param("status") DeviceStatus status,
            @Param("cutoff") LocalDateTime cutoff
    );

    /**
     * Conservé pour compatibilité avec les usages existants qui n'ont pas besoin
     * de couvrir le cas NULL (ex: requêtes métier hors moniteur d'inactivité).
     */
    List<Device> findByStatusAndLastSeenAtBefore(DeviceStatus status, LocalDateTime cutoff);

    List<Device> findByLogicalGroup(String logicalGroup);

    List<Device> findByLocation(String location);

    List<Device> findByResponsible(String responsible);
}
