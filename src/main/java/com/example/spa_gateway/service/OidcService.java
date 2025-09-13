package com.example.spa_gateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

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

    private final OidcSessionService oidcSessionService;
    private final WebClient webClient = WebClient.builder().build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${keycloak.auth-server-url}")
    private String keycloakServerUrl;

    @Value("${app.redirect-uri}")
    private String redirectUri;

    @Value("${keycloak.auth-server-url-on-docker}")
    private String keycloakServerUrlOnDocker;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

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

        TokenResponse tokenResponse = sendTokenRequest(requestBody);

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            log.error("Keycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークン取得に失敗しました", "INVALID_TOKEN_RESPONSE");
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

        TokenResponse tokenResponse = sendTokenRequest(requestBody);

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            log.error("リフレッシュ時にKeycloakから無効なトークンレスポンスを受信しました");
            throw new OidcAuthenticationException("トークンの更新に失敗しました。再度ログインしてください", "INVALID_REFRESH_RESPONSE");
        }

        return tokenResponse;
    }

    /**
     * IDトークンを検証する
     */
    public void validateIdToken(String idToken, String nonce) {
        if (idToken == null || idToken.trim().isEmpty()) {
            log.warn("IDトークンがnullまたは空文字です");
            throw new OidcAuthenticationException("IDトークンが見つかりません", "MISSING_ID_TOKEN");
        }

        try {
            // 1. JWTデコード（署名検証前の基本チェック）
            DecodedJWT jwt = JWT.decode(idToken);
            log.debug("IDトークンデコード成功");

            // 2. 公開鍵を取得してJWT署名検証
            RSAPublicKey publicKey = getKeycloakPublicKey(jwt.getKeyId());
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(keycloakServerUrlOnDocker + "/realms/" + realm)
                .withAudience(clientId)
                .build();

            DecodedJWT verifiedJWT = verifier.verify(idToken);
            log.debug("IDトークン署名検証成功");

            // 3. nonce検証
            String tokenNonce = verifiedJWT.getClaim("nonce").asString();
            if (nonce == null || !nonce.equals(tokenNonce)) {
                log.error("nonce検証失敗: expected={}, actual={}", nonce, tokenNonce);
                throw new OidcAuthenticationException("IDトークンのnonce検証に失敗しました", "INVALID_NONCE");
            }

            // 4. 有効期限検証（JWTVerifierで自動検証されるが、ログ出力）
            Date expiresAt = verifiedJWT.getExpiresAt();
            Date now = new Date();
            if (expiresAt.before(now)) {
                log.error("IDトークンの有効期限切れ: expiresAt={}, now={}", expiresAt, now);
                throw new OidcAuthenticationException("IDトークンの有効期限が切れています", "TOKEN_EXPIRED");
            }

            log.info("IDトークン検証完了: subject={}, nonce={}", verifiedJWT.getSubject(), tokenNonce);

        } catch (JWTDecodeException ex) {
            log.error("IDトークンのデコードに失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("IDトークンの形式が無効です", "INVALID_ID_TOKEN_FORMAT", ex);
        } catch (JWTVerificationException ex) {
            log.error("IDトークンの検証に失敗しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("IDトークンの検証に失敗しました", "ID_TOKEN_VERIFICATION_FAILED", ex);
        } catch (Exception ex) {
            log.error("IDトークン検証中に予期しないエラーが発生しました: {}", ex.getMessage(), ex);
            throw new OidcAuthenticationException("IDトークン検証に失敗しました", "ID_TOKEN_VALIDATION_ERROR", ex);
        }
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
    private TokenResponse sendTokenRequest(MultiValueMap<String, String> requestBody) {
        String url = buildKeycloakTokenEndpoint();

        try {
            log.debug("Keycloakトークンエンドポイントにリクエスト送信中: {}", url);
            return webClient.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(requestBody))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .block();
        } catch (WebClientResponseException ex) {
            log.error("トークン取得でHTTPクライアントエラー: {} - {}", ex.getStatusCode(), ex.getStatusText(), ex);
            throw new OidcAuthenticationException("認証に失敗しました: " + ex.getStatusText(), "TOKEN_REQUEST_FAILED", ex);
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

    /**
     * Keycloakから公開鍵を取得してRSAPublicKeyを構築する
     */
    private RSAPublicKey getKeycloakPublicKey(String keyId) {
        try {
            String jwksUri = UriComponentsBuilder.fromUriString(keycloakServerUrlOnDocker)
                .pathSegment("realms", realm, "protocol", "openid-connect", "certs")
                .build()
                .toUriString();

            log.debug("JWKS URI: {}", jwksUri);

            // JWKSエンドポイントから公開鍵情報を取得
            String jwksResponse = webClient.get()
                .uri(jwksUri)
                .retrieve()
                .bodyToMono(String.class)
                .block();

            JsonNode jwks = objectMapper.readTree(jwksResponse);
            JsonNode keys = jwks.get("keys");

            // keyIdに一致するキーを検索
            for (JsonNode key : keys) {
                String kid = key.get("kid").asText();
                if (keyId == null || keyId.equals(kid)) {
                    // RSA公開鍵の場合のみ処理
                    if ("RSA".equals(key.get("kty").asText())) {
                        String nStr = key.get("n").asText();
                        String eStr = key.get("e").asText();

                        // Base64URLデコード
                        byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
                        byte[] eBytes = Base64.getUrlDecoder().decode(eStr);

                        BigInteger modulus = new BigInteger(1, nBytes);
                        BigInteger exponent = new BigInteger(1, eBytes);

                        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                        KeyFactory factory = KeyFactory.getInstance("RSA");

                        log.debug("RSA公開鍵構築成功: keyId={}", kid);
                        return (RSAPublicKey) factory.generatePublic(spec);
                    }
                }
            }

            throw new OidcAuthenticationException("公開鍵が見つかりません: keyId=" + keyId, "PUBLIC_KEY_NOT_FOUND");

        } catch (Exception ex) {
            log.error("公開鍵取得に失敗しました: keyId={}, error={}", keyId, ex.getMessage(), ex);
            throw new OidcAuthenticationException("公開鍵の取得に失敗しました", "PUBLIC_KEY_FETCH_FAILED", ex);
        }
    }
}