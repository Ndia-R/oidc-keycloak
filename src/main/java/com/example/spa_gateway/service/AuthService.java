package com.example.spa_gateway.service;

import org.springframework.stereotype.Service;

import com.example.spa_gateway.dto.TokenResponse;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
    public TokenResponse login(String username, String password) {
        // Keycloak Token Endpoint に POST してアクセストークン・リフレッシュトークン取得
        // ここでは擬似コード
        return new TokenResponse("ACCESS_TOKEN", "REFRESH_TOKEN", 3600, 30 * 24 * 3600);
    }

    public TokenResponse refresh(String refreshToken) {
        // リフレッシュトークンを Keycloak に送信して新しいアクセストークン取得
        return new TokenResponse("NEW_ACCESS_TOKEN", "NEW_REFRESH_TOKEN", 3600, 30 * 24 * 3600);
    }
}
