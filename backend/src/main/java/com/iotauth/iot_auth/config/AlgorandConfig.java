package com.iotauth.iot_auth.config;

import com.algorand.algosdk.v2.client.common.AlgodClient;
import com.algorand.algosdk.v2.client.common.IndexerClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AlgorandConfig {

    @Bean
    public AlgodClient algodClient(
            @Value("${iot.auth.algorand.algod-address}") String address,
            @Value("${iot.auth.algorand.algod-port}") int port,
            @Value("${iot.auth.algorand.algod-token}") String token
    ) {
        return new AlgodClient(address, port, token);
    }

    @Bean
    public IndexerClient indexerClient(
            @Value("${iot.auth.algorand.indexer-address}") String address,
            @Value("${iot.auth.algorand.indexer-port}") int port,
            @Value("${iot.auth.algorand.indexer-token:}") String token
    ) {
        return new IndexerClient(address, port, token);
    }
}
