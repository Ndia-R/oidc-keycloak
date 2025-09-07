package com.example.spa_gateway.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.exception.OidcAuthenticationException;
import com.example.spa_gateway.service.OidcSessionService;
import com.example.spa_gateway.util.SecurityUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class OidcAuthController {

    private static final Logger logger = LoggerFactory.getLogger(OidcAuthController.class);
    private final OidcSessionService oidcSessionService;

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.auth-server-url-on-docker}")
    private String keycloakServerUrlOnDocker;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Value("${app.redirect-uri}")
    private String redirectUri;

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

        String authorizationEndpoint = keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/auth";
        String url = authorizationEndpoint +
            "?response_type=code" +
            "&client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&scope=openid profile email" +
            "&state=" + state +
            "&nonce=" + nonce +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=S256";
        response.sendRedirect(url);
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

        HttpSession session = request.getSession();

        // Keycloakからのエラーレスポンスを確認
        if (error != null) {
            logger.error("Keycloak認証エラー: {} - {}", error, errorDescription);
            throw new OidcAuthenticationException(
                errorDescription != null ? errorDescription : "認証に失敗しました",
                error.toUpperCase()
            );
        }

        // 必須パラメータの検証
        if (code == null || state == null) {
            logger.error("認証コールバックに必要なパラメータが不足しています: code={}, state={}", code, state);
            throw new OidcAuthenticationException("認証パラメータが不正です", "INVALID_PARAMETERS");
        }

        // CSRF攻撃対策のためstateパラメータを検証
        if (!oidcSessionService.validateState(session, state)) {
            logger.error("不正なstateパラメータです: {}", state);
            throw new OidcAuthenticationException("不正なリクエストです", "INVALID_STATE");
        }

        // PKCEのためcode_verifierを取得
        String codeVerifier = oidcSessionService.getAndRemoveCodeVerifier(session);
        if (codeVerifier == null) {
            logger.error("セッションにcode_verifierが存在しません");
            throw new OidcAuthenticationException("認証セッションが無効です", "MISSING_CODE_VERIFIER");
        }

        String url = keycloakServerUrlOnDocker + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("code_verifier", codeVerifier);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<TokenResponse> tokenResponse;

        try {
            logger.debug("Keycloakトークンエンドポイントにリクエスト送信中: {}", url);
            tokenResponse = restTemplate.postForEntity(
                url,
                new HttpEntity<>(body, headers),
                TokenResponse.class
            );
        } catch (Exception ex) {
            logger.error("トークン取得リクエストに失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスとの通信に失敗しました", "TOKEN_REQUEST_FAILED", ex);
        }

        TokenResponse tokens = tokenResponse.getBody();
        if (tokens == null || tokens.getAccessToken() == null) {
            logger.error("Keycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークン取得に失敗しました", "INVALID_TOKEN_RESPONSE");
        }

        // リフレッシュトークンをHttpOnly Cookieに保存（7日間有効）
        if (tokens.getRefreshToken() != null) {
            SecurityUtils.setSecureHttpOnlyCookie(
                response,
                "refresh_token",
                tokens.getRefreshToken(),
                7 * 24 * 60 * 60
            );
        }

        // TODO: IDトークン検証機能実装時にnonceの検証を追加

        // アクセストークンのみJSONで返却
        AccessTokenResponse accessResponse = new AccessTokenResponse(
            tokens.getAccessToken(),
            tokens.getExpiresIn(),
            tokens.getTokenType(),
            tokens.getScope()
        );

        return ResponseEntity.ok(accessResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AccessTokenResponse> refresh(
        HttpServletRequest request,
        HttpServletResponse response
    ) {

        // Cookieからリフレッシュトークンを取得
        String refreshToken = null;
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("refresh_token".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null) {
            logger.warn("リフレッシュトークンがCookieに存在しません");
            throw new OidcAuthenticationException("リフレッシュトークンが見つかりません", "MISSING_REFRESH_TOKEN");
        }

        String url = keycloakServerUrlOnDocker + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<TokenResponse> tokenResponse;

        try {
            logger.debug("リフレッシュトークンでアクセストークン更新中: {}", url);
            tokenResponse = restTemplate.postForEntity(
                url,
                new HttpEntity<>(body, headers),
                TokenResponse.class
            );
        } catch (Exception ex) {
            logger.error("リフレッシュトークンでのトークン更新に失敗しました: {}", ex.getMessage(), ex);
            // リフレッシュトークンが無効になった可能性があるため、Cookieを削除
            SecurityUtils.deleteCookie(response, "refresh_token");
            throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "REFRESH_TOKEN_INVALID", ex);
        }

        TokenResponse tokens = tokenResponse.getBody();
        if (tokens == null || tokens.getAccessToken() == null) {
            logger.error("リフレッシュ時にKeycloakから無効なトークンレスポンスを受信しました");
            SecurityUtils.deleteCookie(response, "refresh_token");
            throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "INVALID_REFRESH_RESPONSE");
        }

        // 新しいリフレッシュトークンをCookieに保存（存在する場合）
        if (tokens.getRefreshToken() != null) {
            SecurityUtils.setSecureHttpOnlyCookie(
                response,
                "refresh_token",
                tokens.getRefreshToken(),
                7 * 24 * 60 * 60
            );
        }

        // アクセストークンのみJSONで返却
        AccessTokenResponse accessResponse = new AccessTokenResponse(
            tokens.getAccessToken(),
            tokens.getExpiresIn(),
            tokens.getTokenType(),
            tokens.getScope()
        );

        return ResponseEntity.ok(accessResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        // リフレッシュトークンCookieを削除
        SecurityUtils.deleteCookie(response, "refresh_token");
        return ResponseEntity.ok().build();
    }
}
