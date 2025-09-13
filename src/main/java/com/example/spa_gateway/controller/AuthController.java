package com.example.spa_gateway.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.LoginRequest;
import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.service.AuthService;
import com.example.spa_gateway.util.SecurityUtils;

@RestController
@RequestMapping("/auth-with-password")
@RequiredArgsConstructor
public class AuthController {
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    private static final String COOKIE_PATH = "/auth-with-password";

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AccessTokenResponse> login(
        @RequestBody LoginRequest request,
        HttpServletResponse response
    ) {
        // Keycloak に認証リクエスト
        TokenResponse token = authService.login(request.getEmail(), request.getPassword());

        // リフレッシュトークンを HttpOnly Cookie に格納
        SecurityUtils.saveRefreshTokenToCookie(
            response,
            REFRESH_TOKEN_COOKIE_NAME,
            token.getRefreshToken(),
            token.getRefreshExpiresIn(),
            COOKIE_PATH
        );

        return ResponseEntity.ok(SecurityUtils.createAccessTokenResponse(token));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
        @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken,
        HttpServletResponse response
    ) {
        // リフレッシュトークン検証
        authService.validateRefreshToken(refreshToken);

        // トークン更新処理
        TokenResponse token = authService.refreshAccessToken(refreshToken);

        // 新しいリフレッシュトークンを HttpOnly Cookie に格納
        SecurityUtils.saveRefreshTokenToCookie(
            response,
            REFRESH_TOKEN_COOKIE_NAME,
            token.getRefreshToken(),
            token.getRefreshExpiresIn(),
            COOKIE_PATH
        );

        return ResponseEntity.ok(SecurityUtils.createAccessTokenResponse(token));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // リフレッシュトークンCookieを削除
        SecurityUtils.deleteCookie(response, REFRESH_TOKEN_COOKIE_NAME, COOKIE_PATH);
        return ResponseEntity.ok().build();
    }
}
