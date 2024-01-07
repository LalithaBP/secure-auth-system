package com.example.secure_auth_system.service;

import com.example.secure_auth_system.entity.User;
import com.example.secure_auth_system.repository.UserRepository;
import com.example.secure_auth_system.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;


    public String signup(String username, String password, String role) {
        Optional<User> existingUser = userRepository.findByUsername(username);

        if (existingUser.isPresent()) {
            return "Username already taken!";
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password)); // Hash the password
        if (role != null && !role.isEmpty()) {
            user.setRole(role); // set role from request
        } else {
            user.setRole("USER"); // default to USER if not specified
        }
        userRepository.save(user);

        userRepository.save(user);

        return "Signup successful!";
    }

    public Map<String, String> login(String username, String password) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            throw new RuntimeException("Invalid username!");
        }

        User user = userOptional.get();

        if (passwordEncoder.matches(password, user.getPassword())) {
            String accessToken = jwtUtil.generateToken(username, user.getRole(), 10 * 60 * 1000);
            String refreshToken = jwtUtil.generateToken(username, user.getRole(), 7 * 24 * 60 * 60 * 1000);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);

            return tokens;
        } else {
            throw new RuntimeException("Invalid password!");
        }
    }


}
