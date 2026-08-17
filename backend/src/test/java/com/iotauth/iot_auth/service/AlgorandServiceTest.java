package com.iotauth.iot_auth.service;

import com.algorand.algosdk.account.Account;
import com.algorand.algosdk.v2.client.common.AlgodClient;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

class AlgorandServiceTest {

    @Test
    void constructor_doesNotThrow() {
        AlgodClient algodClient = mock(AlgodClient.class);
        Account account = mock(Account.class);
        AuditLogService auditLogService = mock(AuditLogService.class);

        AlgorandService service = new AlgorandService(algodClient, account, auditLogService);
        ReflectionTestUtils.setField(service, "appId", 1001L);

        assertNotNull(service);
    }
}