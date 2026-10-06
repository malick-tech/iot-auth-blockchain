package com.iotauth.iot_auth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientIpResolverTest {

    private HttpServletRequest request(String remoteAddr, String forwardedFor) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn(remoteAddr);
        when(request.getHeader("X-Forwarded-For")).thenReturn(forwardedFor);
        return request;
    }

    @Test
    void resolve_fromTrustedProxy_readsFirstForwardedAddress() {
        assertThat(ClientIpResolver.resolve(request("172.18.0.3", "198.51.100.7, 172.18.0.3")))
                .isEqualTo("198.51.100.7");
    }

    @Test
    void resolve_fromUntrustedAddress_ignoresSpoofedForwardedHeader() {
        assertThat(ClientIpResolver.resolve(request("203.0.113.9", "10.0.0.1")))
                .isEqualTo("203.0.113.9");
    }

    @Test
    void resolve_withoutHeader_usesRemoteAddress() {
        assertThat(ClientIpResolver.resolve(request("127.0.0.1", null))).isEqualTo("127.0.0.1");
    }

    @Test
    void isFromTrustedProxy_recognisesInternalRangesOnly() {
        assertThat(ClientIpResolver.isFromTrustedProxy(request("192.168.1.10", null))).isTrue();
        assertThat(ClientIpResolver.isFromTrustedProxy(request("::1", null))).isTrue();
        assertThat(ClientIpResolver.isFromTrustedProxy(request("203.0.113.9", null))).isFalse();
    }
}
