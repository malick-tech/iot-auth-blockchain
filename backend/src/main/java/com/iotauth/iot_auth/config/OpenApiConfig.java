package com.iotauth.iot_auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI iotAuthOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("IoT Auth Blockchain API")
                        .version("1.0.0")
                        .description("API de gestion des identites DID, de l'enrollment, de l'authentification et des operations IoT.")
                        .contact(new Contact().name("IoT Auth Team")))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("JWT admin obtenu via POST /api/admin/auth/login")));
    }
}