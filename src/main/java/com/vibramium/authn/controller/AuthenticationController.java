package com.vibramium.authn.controller;

import com.vibramium.authn.dto.AuthResponse;
import com.vibramium.authn.dto.AuthenticationRequest;
import com.vibramium.authn.dto.UserRegisterRequest;
import com.vibramium.authn.service.UserAuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final UserAuthenticationService userAuthenticationService;

    public AuthenticationController(UserAuthenticationService userAuthenticationService) {
        this.userAuthenticationService = userAuthenticationService;
    }

    @PostMapping("/getToken")
    public AuthResponse getToken(@RequestBody AuthenticationRequest request) {
        return userAuthenticationService.authenticate(request);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody UserRegisterRequest request) {
        return ResponseEntity.ok(userAuthenticationService.register(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestBody AuthResponse request) {
        return ResponseEntity.ok(userAuthenticationService.validateToken(request));
    }

}
