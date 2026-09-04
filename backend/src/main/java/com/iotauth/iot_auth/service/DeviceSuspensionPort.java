package com.iotauth.iot_auth.service;

import com.iotauth.iot_auth.dto.request.RevocationRequest;

/**
 * Port de suspension de dispositif exposé aux composants qui déclenchent
 * une suspension automatique (ex: AnomalyDetectionService) sans avoir besoin
 * de connaître l'implémentation complète de RevocationService.
 *
 * Ce découplage rompt le cycle de dépendances circulaire :
 * - Avant : AnomalyDetectionService → RevocationService → (dépendances lourdes)
 * - Après : AnomalyDetectionService → DeviceSuspensionPort ← RevocationService
 *
 * RevocationService implémente cette interface ; AnomalyDetectionService
 * consomme uniquement l'interface, pas le bean concret.
 */
public interface DeviceSuspensionPort {

    /**
     * Suspend le dispositif identifié par son DID.
     * La suspension est réversible et n'écrit pas sur Algorand.
     *
     * @param did     DID du dispositif à suspendre
     * @param request raison et métadonnées de la suspension
     */
    void suspendDevice(String did, RevocationRequest request);
}
