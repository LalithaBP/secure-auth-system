package com.example.secure_auth_system.controller;

import com.example.secure_auth_system.dto.AuthRequest;
import com.example.secure_auth_system.entity.User;
import com.example.secure_auth_system.repository.UserRepository;
import com.example.secure_auth_system.service.AuthService;
import com.example.secure_auth_system.token.RefreshTokenStore;
import com.example.secure_auth_system.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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

    @Autowired
    private RefreshTokenStore refreshTokenStore;

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody @Valid AuthRequest request) {
        Map<String, String> tokens = authService.login(request.getUsername(), request.getPassword());

        // Now add refresh token after you got it
        refreshTokenStore.addToken(tokens.get("refreshToken"));

        return tokens;
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

        // 🔥 First check if refresh token exists in store
        if (!refreshTokenStore.contains(refreshToken)) {
            throw new RuntimeException("Invalid Refresh Token!");
        }

        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new RuntimeException("Invalid or expired Refresh Token!");
        }

        // Now safe to generate new Access Token
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new RuntimeException("User not found!")
        );

        String newAccessToken = jwtUtil.generateToken(username, user.getRole(), 10 * 60 * 1000);

        Map<String, String> response = new HashMap<>();
        response.put("accessToken", newAccessToken);
        return response;
    }


    @GetMapping("admin/dashboard")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminDashboard() {
        return "Welcome to Admin Dashboard!";
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        refreshTokenStore.removeToken(refreshToken);
        return ResponseEntity.ok("Logged out successfully!");
    }



}
