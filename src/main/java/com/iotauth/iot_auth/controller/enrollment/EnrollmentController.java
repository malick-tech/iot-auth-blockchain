package com.iotauth.iot_auth.controller.enrollment;

import com.iotauth.iot_auth.dto.request.ChallengeResponseRequest;
import com.iotauth.iot_auth.dto.request.FirstContactRequest;
import com.iotauth.iot_auth.dto.response.ChallengeResponse;
import com.iotauth.iot_auth.dto.response.JwtPopResponse;
import com.iotauth.iot_auth.service.EnrollmentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/enrollment", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class EnrollmentController {

    private final EnrollmentService enrollmentService;

    @PostMapping(path = "/first-contact", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ChallengeResponse firstContact(@Valid @RequestBody FirstContactRequest request) {
        return enrollmentService.handleFirstContact(request);
    }

    @PostMapping(path = "/challenge-response", consumes = MediaType.APPLICATION_JSON_VALUE)
    public JwtPopResponse challengeResponse(@Valid @RequestBody ChallengeResponseRequest request) {
        return enrollmentService.handleChallengeResponse(request);
    }
}
