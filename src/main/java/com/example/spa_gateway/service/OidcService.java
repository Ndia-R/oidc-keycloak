package com.example.spa_gateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.example.spa_gateway.dto.TokenResponse;
import com.example.spa_gateway.exception.OidcAuthenticationException;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class OidcService {
    private static final String DEFAULT_SCOPE = "openid profile email";
    private static final String PKCE_CODE_CHALLENGE_METHOD = "S256";

    private final RestTemplate restTemplate = new RestTemplate();
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

    /**
     * 認証URLを構築する
     */
    public String buildAuthorizationUrl(String state, String nonce, String codeChallenge) {
        return UriComponentsBuilder.fromUriString(keycloakServerUrl)
            .pathSegment("realms", realm, "protocol", "openid-connect", "auth")
            .queryParam("response_type", "code")
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri)
            .queryParam("scope", DEFAULT_SCOPE)
            .queryParam("state", state)
            .queryParam("nonce", nonce)
            .queryParam("code_challenge", codeChallenge)
            .queryParam("code_challenge_method", PKCE_CODE_CHALLENGE_METHOD)
            .build()
            .toUriString();
    }

    /**
     * コールバックエラーを検証する
     */
    public void validateCallbackError(String error, String errorDescription) {
        if (error != null) {
            log.error("Keycloak認証エラー: {} - {}", error, errorDescription);
            throw new OidcAuthenticationException(
                errorDescription != null ? errorDescription : "認証に失敗しました",
                error.toUpperCase()
            );
        }
    }

    /**
     * コールバックパラメータを検証する
     */
    public void validateCallbackParameters(String code, String state) {
        if (code == null || state == null) {
            log.error("認証コールバックに必要なパラメータが不足しています: code={}, state={}", code, state);
            throw new OidcAuthenticationException("認証パラメータが不正です", "INVALID_PARAMETERS");
        }
    }

    /**
     * セッションセキュリティを検証し、code_verifierを返す
     */
    public String validateSessionSecurity(HttpSession session, String state) {
        // CSRF攻撃対策のためstateパラメータを検証
        if (!oidcSessionService.validateState(session, state)) {
            log.error("不正なstateパラメータです: {}", state);
            throw new OidcAuthenticationException("不正なリクエストです", "INVALID_STATE");
        }

        // PKCEのためcode_verifierを取得
        String codeVerifier = oidcSessionService.getAndRemoveCodeVerifier(session);
        if (codeVerifier == null) {
            log.error("セッションにcode_verifierが存在しません");
            throw new OidcAuthenticationException("認証セッションが無効です", "MISSING_CODE_VERIFIER");
        }

        return codeVerifier;
    }

    /**
     * 認可コードをトークンに交換する
     */
    public TokenResponse exchangeCodeForTokens(String code, String codeVerifier) {
        MultiValueMap<String, String> requestBody = createAuthorizationCodeTokenRequestBody(
            code,
            redirectUri,
            codeVerifier
        );

        ResponseEntity<TokenResponse> tokenResponse = sendTokenRequest(requestBody);
        TokenResponse tokens = tokenResponse.getBody();

        if (tokens == null || tokens.getAccessToken() == null) {
            log.error("Keycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークン取得に失敗しました", "INVALID_TOKEN_RESPONSE");
        }

        return tokens;
    }

    /**
     * リフレッシュトークンを検証する
     */
    public void validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            log.warn("リフレッシュトークンがCookieに存在しないか空文字です");
            throw new OidcAuthenticationException("リフレッシュトークンが見つかりません", "MISSING_REFRESH_TOKEN");
        }
    }

    /**
     * リフレッシュトークンでアクセストークンを更新する
     */
    public TokenResponse refreshAccessToken(String refreshToken) {
        MultiValueMap<String, String> requestBody = createRefreshTokenRequestBody(refreshToken);

        ResponseEntity<TokenResponse> tokenResponse = sendTokenRequest(requestBody);
        TokenResponse tokens = tokenResponse.getBody();

        if (tokens == null || tokens.getAccessToken() == null) {
            log.error("リフレッシュ時にKeycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "INVALID_REFRESH_RESPONSE");
        }

        return tokens;
    }

    // ========== プライベートメソッド ==========

    /**
     * Keycloakトークンエンドポイント用のリクエストボディを作成する（認可コード用）
     */
    private MultiValueMap<String, String> createAuthorizationCodeTokenRequestBody(
        String code,
        String redirectUri,
        String codeVerifier
    ) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("code_verifier", codeVerifier);
        return body;
    }

    /**
     * Keycloakトークンエンドポイント用のリクエストボディを作成する（リフレッシュトークン用）
     */
    private MultiValueMap<String, String> createRefreshTokenRequestBody(String refreshToken) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);
        return body;
    }

    /**
     * Keycloakにトークンリクエストを送信する
     */
    private ResponseEntity<TokenResponse> sendTokenRequest(MultiValueMap<String, String> requestBody) {
        String url = buildKeycloakTokenEndpoint();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        try {
            log.debug("Keycloakトークンエンドポイントにリクエスト送信中: {}", url);
            return restTemplate.postForEntity(
                url,
                new HttpEntity<>(requestBody, headers),
                TokenResponse.class
            );
        } catch (HttpClientErrorException ex) {
            log.error("トークン取得でHTTPクライアントエラー: {} - {}", ex.getStatusCode(), ex.getStatusText(), ex);
            throw new OidcAuthenticationException("認証に失敗しました: " + ex.getStatusText(), "TOKEN_REQUEST_FAILED", ex);
        } catch (ResourceAccessException ex) {
            log.error("認証サービスへの接続に失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスに接続できません", "SERVICE_UNAVAILABLE", ex);
        } catch (Exception ex) {
            log.error("トークン取得リクエストに失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスとの通信に失敗しました", "TOKEN_REQUEST_FAILED", ex);
        }
    }

    /**
     * KeycloakトークンエンドポイントURLを構築する
     */
    private String buildKeycloakTokenEndpoint() {
        return UriComponentsBuilder.fromUriString(keycloakServerUrlOnDocker)
            .pathSegment("realms", realm, "protocol", "openid-connect", "token")
            .build()
            .toUriString();
    }
}