package com.iotauth.iot_auth.config;

import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.v2.client.common.AlgodClient;
import com.algorand.algosdk.v2.client.common.IndexerClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.GeneralSecurityException;

@Configuration
@Slf4j
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

    /**
     * Compte Algorand (LocalNet) autorise a signer les transactions
     * d'ecriture sur le smart contract (PUBLISH_DID, UPDATE_STATUS).
     * Correspond au compte "Admin" qui a deploye le contrat.
     */
    @Bean
    public Account algorandAdminAccount(
            @Value("${iot.auth.algorand.deployer-mnemonic}") String mnemonic,
            @Value("${spring.datasource.url:}") String datasourceUrl
    ) throws GeneralSecurityException {
        if (mnemonic == null || mnemonic.isBlank()) {
            if (datasourceUrl.startsWith("jdbc:h2:")) {
                return new Account();
            }
            throw new IllegalStateException(
                "ALGORAND_DEPLOYER_MNEMONIC est obligatoire pour le profil local. "
                    + "Il doit correspondre au compte admin du contrat Algorand (application 1014). "
                    + "Definissez la variable dans le terminal avant de demarrer Spring Boot."
            );
        }
        return new Account(mnemonic);
    }

    @Bean
    public org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder passwordEncoder() {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }
}
