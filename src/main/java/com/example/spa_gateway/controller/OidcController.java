package com.example.spa_gateway.controller;

import java.io.IOException;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.service.OidcService;
import com.example.spa_gateway.service.OidcSessionService;
import com.example.spa_gateway.util.SecurityUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class OidcController {
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    private static final String COOKIE_PATH = "/auth";

    private final OidcService oidcService;
    private final OidcSessionService oidcSessionService;

    @GetMapping("/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();

        // セキュリティのためstate、nonce、PKCEパラメータを生成
        String state = SecurityUtils.generateState();
        String nonce = SecurityUtils.generateNonce();
        String codeVerifier = SecurityUtils.generateCodeVerifier();
        String codeChallenge = SecurityUtils.generateCodeChallenge(codeVerifier);

        // セッションにstate、nonce、code_verifierを保存
        oidcSessionService.storeState(session, state);
        oidcSessionService.storeNonce(session, nonce);
        oidcSessionService.storeCodeVerifier(session, codeVerifier);

        // 認証URLを構築し、リダイレクト
        String authorizationUrl = oidcService.buildAuthorizationUrl(state, nonce, codeChallenge);
        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/callback")
    public ResponseEntity<AccessTokenResponse> callback(
        @RequestParam(required = false) String code,
        @RequestParam(required = false) String state,
        @RequestParam(required = false) String error,
        @RequestParam(required = false) String errorDescription,
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        // エラーレスポンス確認
        oidcService.validateCallbackError(error, errorDescription);

        // パラメータ検証
        oidcService.validateCallbackParameters(code, state);

        // セキュリティ検証
        HttpSession session = request.getSession();
        String codeVerifier = oidcService.validateSessionSecurity(session, state);

        // トークン交換処理
        TokenResponse tokens = oidcService.exchangeCodeForTokens(code, codeVerifier);

        // IDトークン検証
        String nonce = oidcSessionService.getNonce(session);
        oidcService.validateIdToken(tokens.getIdToken(), nonce);

        // リフレッシュトークンを HttpOnly Cookie に格納
        SecurityUtils.saveRefreshTokenToCookie(
            response,
            REFRESH_TOKEN_COOKIE_NAME,
            tokens.getRefreshToken(),
            tokens.getRefreshExpiresIn(),
            COOKIE_PATH
        );

        return ResponseEntity.ok(SecurityUtils.createAccessTokenResponse(tokens));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
        @CookieValue(name = REFRESH_TOKEN_COOKIE_NAME, required = false) String refreshToken,
        HttpServletResponse response
    ) {
        // リフレッシュトークン検証
        oidcService.validateRefreshToken(refreshToken);

        // トークン更新処理
        TokenResponse tokens = oidcService.refreshAccessToken(refreshToken);

        // 新しいリフレッシュトークンを HttpOnly Cookie に格納
        SecurityUtils.saveRefreshTokenToCookie(
            response,
            REFRESH_TOKEN_COOKIE_NAME,
            tokens.getRefreshToken(),
            tokens.getRefreshExpiresIn(),
            COOKIE_PATH
        );

        return ResponseEntity.ok(SecurityUtils.createAccessTokenResponse(tokens));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // リフレッシュトークンCookieを削除
        SecurityUtils.deleteCookie(response, REFRESH_TOKEN_COOKIE_NAME, COOKIE_PATH);
        return ResponseEntity.ok().build();
    }
}
