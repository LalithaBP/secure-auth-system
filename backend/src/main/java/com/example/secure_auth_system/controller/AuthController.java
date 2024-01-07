package com.example.secure_auth_system.controller;

import com.example.secure_auth_system.dto.AuthRequest;
import com.example.secure_auth_system.entity.User;
import com.example.secure_auth_system.repository.UserRepository;
import com.example.secure_auth_system.service.AuthService;
import com.example.secure_auth_system.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.constraints.NotBlank;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody @Valid AuthRequest request) {
        return authService.login(request.getUsername(), request.getPassword());
    }


    @PostMapping("/signup")
    public String signup(@RequestBody @Valid AuthRequest request) {
        return authService.signup(request.getUsername(), request.getPassword(), request.getRole());
    }

    @GetMapping("/api/test/secure")
    public String secureEndpoint() {
        return "You have access to secured endpoint!";
    }

    @PostMapping("/refresh")
    public Map<String, String> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        String username = jwtUtil.extractUsername(refreshToken);

        if (jwtUtil.validateToken(refreshToken, username)) {
            User user = userRepository.findByUsername(username).orElseThrow(
                    () -> new RuntimeException("User not found!")
            );
            String newAccessToken = jwtUtil.generateToken(username, user.getRole(), 10 * 60 * 1000);

            //String newAccessToken = jwtUtil.generateToken(username, "ADMIN", 10 * 60 * 1000); // 10 minutes
            Map<String, String> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            return response;
        } else {
            throw new RuntimeException("Invalid Refresh Token!");
        }
    }

    @GetMapping("admin/dashboard")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminDashboard() {
        return "Welcome to Admin Dashboard!";
    }



}
