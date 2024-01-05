package com.example.secure_auth_system.dto;
import jakarta.validation.constraints.NotBlank;


import lombok.Data;

@Data
public class AuthRequest {
    @NotBlank(message = "Username must not be blank")
    private String username;
    private String password;
}
