package com.iotauth.iot_auth.controller.operational;

import com.iotauth.iot_auth.service.StatusListService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Publie les BitstringStatusListCredential (W3C Bitstring Status List v1.0). Endpoint public, lecture seule. */
@RestController
@RequestMapping("/api/v1/status-lists")
@RequiredArgsConstructor
public class StatusListController {

    private final StatusListService statusListService;

    @GetMapping(path = "/{purpose}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> get(@PathVariable String purpose) {
        if (!StatusListService.isValidPurpose(purpose)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(statusListService.buildStatusListCredential(purpose));
    }
}
