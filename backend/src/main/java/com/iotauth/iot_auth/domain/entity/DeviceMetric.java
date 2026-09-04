package com.iotauth.iot_auth.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Métriques opérationnelles remontées par un dispositif IoT lors d'une
 * vérification JWT PoP réussie.
 *
 * Chaque ligne correspond à un paquet de métriques reçu et accepté
 * (le dispositif était ACTIVE et la preuve de possession valide).
 * Les lignes refusées ne sont pas persistées.
 */
@Entity
@Table(
        name = "device_metrics",
        indexes = {
                @Index(name = "idx_metrics_did", columnList = "device_did"),
                @Index(name = "idx_metrics_measured_at", columnList = "measured_at"),
                @Index(name = "idx_metrics_did_measured", columnList = "device_did, measured_at")
        }
)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceMetric {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    /** DID du dispositif qui a envoyé les métriques. */
    @Column(name = "device_did", nullable = false)
    private String deviceDid;

    /** Température en degrés Celsius (peut être null si le capteur ne la remonte pas). */
    @Column(name = "temperature_c")
    private Double temperatureC;

    /** Humidité relative en % (peut être null). */
    @Column(name = "humidity_percent")
    private Double humidityPercent;

    /** Niveau de batterie en % (peut être null). */
    @Column(name = "battery_percent")
    private Double batteryPercent;

    /** Temps de fonctionnement en secondes depuis le dernier redémarrage (peut être null). */
    @Column(name = "uptime_seconds")
    private Long uptimeSeconds;

    /** Horodatage de mesure fourni par le dispositif (epoch Unix, peut être null). */
    @Column(name = "measured_at")
    private Instant measuredAt;

    /** Horodatage de réception par le backend (toujours renseigné). */
    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;
}
