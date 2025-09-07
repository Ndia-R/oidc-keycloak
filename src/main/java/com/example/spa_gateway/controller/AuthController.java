package com.example.spa_gateway.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.spa_gateway.dto.LoginRequest;
import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.service.AuthService;

@RestController
@RequestMapping("/auth-with-password")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // SPA から login リクエスト
    @PostMapping("/login")
    public ResponseEntity<?> login(
        @RequestBody LoginRequest request,
        HttpServletResponse response
    ) {

        // Keycloak に認証リクエスト
        TokenResponse token = authService.login(request.getEmail(), request.getPassword());

        // リフレッシュトークンを HttpOnly Cookie に格納
        Cookie cookie = new Cookie("refreshToken", token.getRefreshToken());
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // HTTPS 必須
        cookie.setPath("/auth");
        cookie.setMaxAge(token.getRefreshExpiresIn());
        response.addCookie(cookie);

        // アクセストークンを JSON で返す
        return ResponseEntity.ok(new AccessTokenResponse(token.getAccessToken(), token.getExpiresIn()));
    }

    // リフレッシュ
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
        @CookieValue(name = "refreshToken") String refreshToken,
        HttpServletResponse response
    ) {
        TokenResponse token = authService.refresh(refreshToken);

        // Cookie 更新
        Cookie cookie = new Cookie("refreshToken", token.getRefreshToken());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(token.getRefreshExpiresIn());
        response.addCookie(cookie);

        return ResponseEntity.ok(new AccessTokenResponse(token.getAccessToken(), token.getExpiresIn()));
    }

    // ログアウト
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        // Cookie を削除
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok().build();
    }

    // レスポンス DTO
    public record AccessTokenResponse(String accessToken, long expiresIn) {
    }
}
