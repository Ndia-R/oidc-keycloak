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

    public TokenResponse login(String username, String password) {
        log.debug("ユーザー認証開始: {}", username);
        
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "password");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("username", username);
            params.add("password", password);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String tokenUrl = buildKeycloakTokenEndpoint();
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            
            log.debug("Keycloakトークンエンドポイントにリクエスト送信中: {}", tokenUrl);
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUrl, request, TokenResponse.class);

            TokenResponse tokenResponse = response.getBody();
            if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
                log.error("Keycloakから無効なトークンレスポンスを受信しました");
                throw new OidcAuthenticationException("認証に失敗しました", "INVALID_TOKEN_RESPONSE");
            }

            log.debug("ユーザー認証成功: {}", username);
            return tokenResponse;
            
        } catch (HttpClientErrorException ex) {
            log.error("認証でHTTPクライアントエラー: {} - {}", ex.getStatusCode(), ex.getStatusText(), ex);
            throw new OidcAuthenticationException("認証に失敗しました: " + ex.getStatusText(), "AUTH_FAILED", ex);
        } catch (ResourceAccessException ex) {
            log.error("認証サービスへの接続に失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスに接続できません", "SERVICE_UNAVAILABLE", ex);
        } catch (Exception ex) {
            log.error("認証リクエストに失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスとの通信に失敗しました", "AUTH_REQUEST_FAILED", ex);
        }
    }

    public TokenResponse refresh(String refreshToken) {
        log.debug("リフレッシュトークンによるアクセストークン更新開始");
        
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            log.warn("リフレッシュトークンが空文字または未設定です");
            throw new OidcAuthenticationException("リフレッシュトークンが見つかりません", "MISSING_REFRESH_TOKEN");
        }
        
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("client_id", clientId);
            params.add("client_secret", clientSecret);
            params.add("refresh_token", refreshToken);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String tokenUrl = buildKeycloakTokenEndpoint();
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            
            log.debug("Keycloakリフレッシュエンドポイントにリクエスト送信中: {}", tokenUrl);
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUrl, request, TokenResponse.class);

            TokenResponse tokenResponse = response.getBody();
            if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
                log.error("リフレッシュ時にKeycloakから無効なトークンレスポンスを受信しました");
                throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "INVALID_REFRESH_RESPONSE");
            }

            log.debug("リフレッシュトークンによる認証成功");
            return tokenResponse;
            
        } catch (HttpClientErrorException ex) {
            log.error("リフレッシュでHTTPクライアントエラー: {} - {}", ex.getStatusCode(), ex.getStatusText(), ex);
            throw new OidcAuthenticationException("トークン更新に失敗しました: " + ex.getStatusText(), "REFRESH_FAILED", ex);
        } catch (ResourceAccessException ex) {
            log.error("認証サービスへの接続に失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスに接続できません", "SERVICE_UNAVAILABLE", ex);
        } catch (Exception ex) {
            log.error("リフレッシュリクエストに失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("認証サービスとの通信に失敗しました", "REFRESH_REQUEST_FAILED", ex);
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
