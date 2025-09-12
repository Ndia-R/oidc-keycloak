package com.example.spa_gateway.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.LoginRequest;
import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.service.AuthService;
import com.example.spa_gateway.util.SecurityUtils;

@Slf4j
@RestController
@RequestMapping("/auth-with-password")
@RequiredArgsConstructor
public class AuthController {
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";
    private static final String COOKIE_PATH = "/auth-with-password";
    private final AuthService authService;

    // SPA から login リクエスト
    @PostMapping("/login")
    public ResponseEntity<AccessTokenResponse> login(
        @RequestBody LoginRequest request,
        HttpServletResponse response
    ) {
        log.debug("メール/パスワード認証開始: {}", request.getEmail());

        // Keycloak に認証リクエスト
        TokenResponse token = authService.login(request.getEmail(), request.getPassword());

        // リフレッシュトークンを HttpOnly Cookie に格納
        saveRefreshTokenToCookie(response, token.getRefreshToken(), token.getRefreshExpiresIn());

        log.debug("メール/パスワード認証成功: {}", request.getEmail());

        // アクセストークンを JSON で返す
        return ResponseEntity.ok(
            new AccessTokenResponse(
                token.getAccessToken(),
                token.getExpiresIn(),
                token.getTokenType(),
                token.getScope()
            )
        );
    }

    // リフレッシュ
    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
        @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken,
        HttpServletResponse response
    ) {
        log.debug("リフレッシュトークンによるアクセストークン更新開始");

        // リフレッシュトークン検証（AuthServiceで詳細検証）
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            log.warn("リフレッシュトークンがCookieに存在しないか空文字です");
            throw new com.example.spa_gateway.exception.OidcAuthenticationException("リフレッシュトークンが見つかりません", "MISSING_REFRESH_TOKEN");
        }

        TokenResponse token = authService.refresh(refreshToken);

        // Cookie 更新
        saveRefreshTokenToCookie(response, token.getRefreshToken(), token.getRefreshExpiresIn());

        log.debug("リフレッシュトークンによる認証成功");

        return ResponseEntity.ok(
            new AccessTokenResponse(
                token.getAccessToken(),
                token.getExpiresIn(),
                token.getTokenType(),
                token.getScope()
            )
        );
    }

    // ログアウト
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        log.debug("ログアウト処理開始");

        // リフレッシュトークンCookieを削除
        SecurityUtils.deleteCookie(response, REFRESH_TOKEN_COOKIE_NAME, COOKIE_PATH);

        log.debug("ログアウト処理完了");

        return ResponseEntity.ok().build();
    }

    // ========== プライベートヘルパーメソッド ==========

    /**
     * リフレッシュトークンをHttpOnly Cookieに保存する
     */
    private void saveRefreshTokenToCookie(HttpServletResponse response, String refreshToken, int maxAge) {
        if (refreshToken != null) {
            SecurityUtils.setSecureHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE_NAME,
                refreshToken,
                maxAge,
                COOKIE_PATH
            );
        }
    }

}
