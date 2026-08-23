package com.iotauth.iot_auth.exception;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DeviceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleDeviceNotFound(DeviceNotFoundException ex) {
        log.warn("Device not found: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.NOT_FOUND, "DEVICE_NOT_FOUND", ex.getMessage());
    }

    @ExceptionHandler(DeviceAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleDeviceAlreadyExists(DeviceAlreadyExistsException ex) {
        log.warn("Device already exists: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.CONFLICT, "DEVICE_ALREADY_EXISTS", ex.getMessage());
    }

    @ExceptionHandler(DeviceSuspendedException.class)
    public ResponseEntity<Map<String, Object>> handleDeviceSuspended(DeviceSuspendedException ex) {
        log.warn("Device suspended: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.FORBIDDEN, "DEVICE_SUSPENDED", ex.getMessage());
    }

    @ExceptionHandler(DeviceRevokedException.class)
    public ResponseEntity<Map<String, Object>> handleDeviceRevoked(DeviceRevokedException ex) {
        log.warn("Device revoked: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.FORBIDDEN, "DEVICE_REVOKED", ex.getMessage());
    }

    @ExceptionHandler(InvalidDeviceStatusException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidDeviceStatus(InvalidDeviceStatusException ex) {
        log.warn("Invalid device status: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_DEVICE_STATUS", ex.getMessage());
    }

    @ExceptionHandler(InvalidSignatureException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidSignature(InvalidSignatureException ex) {
        log.warn("Invalid signature: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "INVALID_SIGNATURE", ex.getMessage());
    }

    @ExceptionHandler(NonceExpiredException.class)
    public ResponseEntity<Map<String, Object>> handleNonceExpired(NonceExpiredException ex) {
        log.warn("Nonce expired: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "NONCE_EXPIRED", ex.getMessage());
    }

    @ExceptionHandler(AdminAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleAdminAlreadyExists(AdminAlreadyExistsException ex) {
        log.warn("Admin already exists: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.CONFLICT, "ADMIN_ALREADY_EXISTS", ex.getMessage());
    }

    @ExceptionHandler(InvalidAdminCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidAdminCredentials(InvalidAdminCredentialsException ex) {
        log.warn("Invalid admin credentials attempt");
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "INVALID_ADMIN_CREDENTIALS", ex.getMessage());
    }

    @ExceptionHandler(UnauthorizedAdminException.class)
    public ResponseEntity<Map<String, Object>> handleUnauthorizedAdmin(UnauthorizedAdminException ex) {
        log.warn("Unauthorized admin access: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(ConstraintViolationException ex) {
        String message = ex.getConstraintViolations()
                .stream()
                .map(violation -> violation.getPropertyPath() + ": " + violation.getMessage())
                .collect(Collectors.joining(", "));
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message);
    }

    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    public ResponseEntity<Map<String, Object>> handleNotFound(Exception ex) {
        log.warn("Route not found: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.NOT_FOUND, "ROUTE_NOT_FOUND", "Route introuvable");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Invalid argument: {}", ex.getMessage());
        return buildErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_ARGUMENT", ex.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException ex) {
        log.error("Illegal state: {}", ex.getMessage(), ex);
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Une erreur systÃ¨me s'est produite");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Une erreur systÃ¨me s'est produite");
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status, String code, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", status.value());
        response.put("error", status.getReasonPhrase());
        response.put("code", code);
        response.put("message", message);
        return ResponseEntity.status(status).body(response);
    }
}
