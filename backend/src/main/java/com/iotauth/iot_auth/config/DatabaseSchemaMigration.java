package com.iotauth.iot_auth.config;

import com.iotauth.iot_auth.domain.enums.EventType;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class DatabaseSchemaMigration {

    private final JdbcTemplate jdbcTemplate;

    @PostConstruct
    void alignAuthLogEventTypeConstraint() {
        String allowedEventTypes = Arrays.stream(EventType.values())
                .map(eventType -> "'" + eventType.name() + "'")
                .collect(Collectors.joining(", "));

        jdbcTemplate.execute("ALTER TABLE auth_logs DROP CONSTRAINT IF EXISTS auth_logs_event_type_check");
        jdbcTemplate.execute("ALTER TABLE auth_logs ADD CONSTRAINT auth_logs_event_type_check "
                + "CHECK (event_type IN (" + allowedEventTypes + "))");
    }
}