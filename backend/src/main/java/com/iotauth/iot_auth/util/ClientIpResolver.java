package com.iotauth.iot_auth.util;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Résolution de l'adresse du client, partagée par le filtre de rate limiting (quota par IP)
 * et les contrôleurs (quota par couple DID + IP).
 *
 * X-Forwarded-For est spoofable si aucun reverse proxy de confiance ne se trouve devant le
 * backend : il n'est lu que si l'adresse TCP directe est celle d'un proxy interne (loopback ou
 * plage privée), ce qui est le cas dans Docker Compose (gateway -> backend via le réseau
 * interne). Dans tous les autres cas on utilise l'adresse de connexion TCP.
 */
public final class ClientIpResolver {

    private ClientIpResolver() {
    }

    public static String resolve(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (isTrustedProxy(remoteAddr)) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                // Première IP de la chaîne (client d'origine)
                return forwarded.split(",")[0].trim();
            }
        }
        return remoteAddr;
    }

    /**
     * True si la requête arrive d'un proxy interne de confiance (gateway) : loopback 127.x,
     * ::1, ou plages RFC-1918. Ces appelants agrègent le trafic de toute la flotte et
     * bénéficient du plafond IP large ; les autres sont limités strictement.
     */
    public static boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null) return false;
        return remoteAddr.equals("127.0.0.1")
                || remoteAddr.equals("::1")
                || remoteAddr.startsWith("10.")
                || remoteAddr.startsWith("172.")
                || remoteAddr.startsWith("192.168.");
    }

    /** Variante pratique : la connexion TCP directe vient-elle d'un proxy de confiance ? */
    public static boolean isFromTrustedProxy(HttpServletRequest request) {
        return isTrustedProxy(request.getRemoteAddr());
    }
}
