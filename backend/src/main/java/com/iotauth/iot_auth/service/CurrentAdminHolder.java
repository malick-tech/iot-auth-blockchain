package com.iotauth.iot_auth.service;

/**
 * Porte le nom de l'admin authentifié pour la durée d'une requête HTTP,
 * posé par AdminAuthFilter et lu automatiquement par AuditLogService -
 * évite de faire transiter ce paramètre à travers toute la pile d'appels.
 */
public final class CurrentAdminHolder {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();
    private static final ThreadLocal<String> CURRENT_FULL_NAME = new ThreadLocal<>();

    private CurrentAdminHolder() {}

    public static void set(String username) {
        CURRENT.set(username);
    }

    public static String get() {
        return CURRENT.get();
    }

    public static void setFullName(String fullName) {
        CURRENT_FULL_NAME.set(fullName);
    }

    public static String getFullName() {
        return CURRENT_FULL_NAME.get();
    }

    public static void clear() {
        CURRENT.remove();
        CURRENT_FULL_NAME.remove();
    }
}