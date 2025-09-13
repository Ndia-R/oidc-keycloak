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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${keycloak.auth-server-url-on-docker}")
    private String keycloakServerUrlOnDocker;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    /**
     * ログイン認証
     */
    public TokenResponse login(String username, String password) {
        MultiValueMap<String, String> requestBody = createLoginRequestBody(username, password);

        ResponseEntity<TokenResponse> response = sendTokenRequest(requestBody);
        TokenResponse tokenResponse = response.getBody();

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            log.error("Keycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("認証に失敗しました", "INVALID_TOKEN_RESPONSE");
        }

        return tokenResponse;
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

        ResponseEntity<TokenResponse> response = sendTokenRequest(requestBody);
        TokenResponse tokenResponse = response.getBody();

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            log.error("リフレッシュ時にKeycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "INVALID_REFRESH_RESPONSE");
        }

        return tokenResponse;
    }

    // ========== プライベートメソッド ==========

    /**
     * ログイン用リクエストボディを作成する
     */
    private MultiValueMap<String, String> createLoginRequestBody(
        String username,
        String password
    ) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", username);
        body.add("password", password);
        return body;
    }

    /**
     * リフレッシュトークン用リクエストボディを作成する
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
