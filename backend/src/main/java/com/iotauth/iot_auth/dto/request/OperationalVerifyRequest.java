package com.iotauth.iot_auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OperationalVerifyRequest {

    @NotBlank
    private String did;

    @NotBlank
    private String jwt;

    private long timestamp;

    @NotBlank
    private String proofSignature;

    private String requestedPermission;

    /**
     * Métriques du dispositif, transmises sous forme de chaîne JSON compacte
     * littérale (et non déjà parsée en Map). La preuve de possession signe le
     * condensat de cette chaîne exacte ; la parser côté serveur avant de la
     * hasher réintroduirait le risque de canonicalisation JSON que l'on évite
     * précisément pour la Verifiable Presentation (cf. chapitre 3).
     */
    private String metricsJson;
}
