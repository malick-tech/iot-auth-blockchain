package com.iotauth.iot_auth.controller.admin;

import com.iotauth.iot_auth.dto.request.AdminLoginRequest;
import com.iotauth.iot_auth.dto.response.AdminLoginResponse;
import com.iotauth.iot_auth.service.AdminAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/admin/auth")
@RequiredArgsConstructor
public class AdminAuthController {

    private final AdminAuthService adminAuthService;

  @PostMapping(path = "/login")
    public AdminLoginResponse login(@Valid @RequestBody AdminLoginRequest request) {
        return adminAuthService.login(request);
    }

    @PostMapping(path = "/register")
    public void register(@Valid @RequestBody com.iotauth.iot_auth.dto.request.AdminRegisterRequest request) {
        adminAuthService.register(request);
    }
}