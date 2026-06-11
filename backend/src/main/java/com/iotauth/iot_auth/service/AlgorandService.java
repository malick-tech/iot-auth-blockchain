package com.iotauth.iot_auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Slf4j
@Service
public class AlgorandService {

    public String publishDidDocument(String did, String publicKey, String metadata) {
        log.info("Publication on-chain simulée pour DID={} metadata={}", did, metadata);
        return "tx-" + UUID.randomUUID();
    }

    public String publishDeviceLifecycleEvent(String did, String status, String reason) {
        log.info("Publication lifecycle on-chain simulée pour DID={} status={} reason={}", did, status, reason);
        return "tx-" + UUID.randomUUID();
    }
}
