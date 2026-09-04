package com.iotauth.iot_auth.controller.admin;

import com.iotauth.iot_auth.dto.response.DeviceMetricResponse;
import com.iotauth.iot_auth.service.DeviceMetricService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * Expose l'historique des métriques IoT à la console d'administration.
 *
 * Toutes les routes sont protégées par AdminAuthFilter + Spring Security (ROLE_ADMIN).
 */
@RestController
@RequestMapping(path = "/api/v1/admin/devices")
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
public class DeviceMetricController {

    private final DeviceMetricService deviceMetricService;

    /**
     * Retourne l'historique paginé des métriques d'un dispositif,
     * du plus récent au plus ancien.
     *
     * @param did   DID du dispositif
     * @param page  numéro de page (0-indexé, défaut 0)
     * @param size  taille de page (défaut 50)
     */
    @GetMapping(path = "/{did}/metrics")
    public Page<DeviceMetricResponse> getMetrics(
            @PathVariable String did,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        PageRequest pageable = PageRequest.of(page, size, Sort.by("measuredAt").descending());
        return deviceMetricService.getMetrics(did, pageable);
    }

    /**
     * Retourne les métriques d'un dispositif dans une fenêtre temporelle.
     *
     * @param did  DID du dispositif
     * @param from début de la fenêtre en epoch Unix (secondes)
     * @param to   fin de la fenêtre en epoch Unix (secondes)
     * @param page numéro de page (0-indexé, défaut 0)
     * @param size taille de page (défaut 50)
     */
    @GetMapping(path = "/{did}/metrics/range")
    public Page<DeviceMetricResponse> getMetricsInRange(
            @PathVariable String did,
            @RequestParam long from,
            @RequestParam long to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        PageRequest pageable = PageRequest.of(page, size, Sort.by("measuredAt").descending());
        return deviceMetricService.getMetricsInRange(
                did,
                Instant.ofEpochSecond(from),
                Instant.ofEpochSecond(to),
                pageable
        );
    }
}
