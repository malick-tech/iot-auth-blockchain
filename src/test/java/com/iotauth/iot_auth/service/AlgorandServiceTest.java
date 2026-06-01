package com.iotauth.iot_auth.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AlgorandServiceTest {

    @Test
    void publishDidDocument_shouldReturnTransactionId() {
        AlgorandService service = new AlgorandService();

        String txId = service.publishDidDocument("did:algo:ABC", "PUBLIC_KEY", "{\"foo\":\"bar\"}");

        assertThat(txId).isNotNull();
        assertThat(txId).startsWith("tx-");
        assertThat(txId.length()).isGreaterThan(3);
    }
}
