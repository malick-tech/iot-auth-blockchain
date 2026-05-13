package com.iotauth.iot_auth.dto.response;

import com.iotauth.iot_auth.domain.entity.VerifiableCredential;
import java.time.Instant;

public record VerifiableCredentialResponse(
        Long id,
        String credentialId,
        String deviceId,
        String issuer,
        String subject,
        String vcHash,
        String algorandTxId,
        boolean revoked,
        Instant issuedAt,
        Instant expiresAt,
        Instant revokedAt
) {

    public static VerifiableCredentialResponse fromEntity(VerifiableCredential credential) {
        return new VerifiableCredentialResponse(
                credential.getId(),
                credential.getCredentialId(),
                credential.getDevice().getDeviceId(),
                credential.getIssuer(),
                credential.getSubject(),
                credential.getVcHash(),
                credential.getAlgorandTxId(),
                credential.isRevoked(),
                credential.getIssuedAt(),
                credential.getExpiresAt(),
                credential.getRevokedAt()
        );
    }
}
