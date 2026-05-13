package com.iotauth.iot_auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AnomalyDetectionService {

    public void recordChallengeFailure(String did) {
        log.warn("Challenge failure recorded for did={}", did);
    }
}
