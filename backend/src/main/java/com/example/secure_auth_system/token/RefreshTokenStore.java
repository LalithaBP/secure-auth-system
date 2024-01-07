package com.example.secure_auth_system.token;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenStore{
    private Set<String> refreshTokens = ConcurrentHashMap.newKeySet();

    public void addToken(String token) {
        refreshTokens.add(token);
    }

    public void removeToken(String token) {
        refreshTokens.remove(token);
    }

    public boolean contains(String token) {
        return refreshTokens.contains(token);
    }
}
