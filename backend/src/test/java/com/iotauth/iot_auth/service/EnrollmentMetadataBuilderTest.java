package com.iotauth.iot_auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iotauth.iot_auth.domain.entity.Device;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Le DID Document est publié sur une chaîne publique et permanente :
 * il ne doit contenir aucune métadonnée de dispositif (serial, type, lieu, groupe).
 */
class EnrollmentMetadataBuilderTest {

    private static final String DID = "did:algo:custom:app:1001:aabbccdd";
    private static final String PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void didDocumentNeContientAucuneMetadonneeDeDispositif() throws Exception {
        Device device = new Device();
        device.setDid(DID);
        device.setPublicKey(PUBLIC_KEY);
        device.setSerialNumber("SN-SECRET-0001");
        device.setDeviceType("temperature-sensor");
        device.setLocation("Dakar-Salle-3");
        device.setLogicalGroup("groupe-confidentiel");

        String document = new EnrollmentMetadataBuilder().build(device);

        assertFalse(document.contains("SN-SECRET-0001"), "le serial ne doit pas etre publie");
        assertFalse(document.contains("temperature-sensor"), "le type ne doit pas etre publie");
        assertFalse(document.contains("Dakar-Salle-3"), "la localisation ne doit pas etre publiee");
        assertFalse(document.contains("groupe-confidentiel"), "le groupe ne doit pas etre publie");
        assertFalse(document.contains("\"service\""), "aucun bloc service attendu");

        JsonNode json = new ObjectMapper().readTree(document);
        assertEquals(DID, json.get("id").asText());
        assertTrue(document.contains(PUBLIC_KEY));
    }
}
