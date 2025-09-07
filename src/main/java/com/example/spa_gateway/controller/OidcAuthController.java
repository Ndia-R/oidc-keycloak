package com.example.spa_gateway.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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

import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.TokenResponse;
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
            @RequestParam String code,
            @RequestParam String state,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        HttpSession session = request.getSession();
        
        // CSRF攻撃対策のためstateパラメータを検証
        if (!oidcSessionService.validateState(session, state)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        
        // PKCEのためcode_verifierを取得
        String codeVerifier = oidcSessionService.getAndRemoveCodeVerifier(session);
        if (codeVerifier == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
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
        ResponseEntity<TokenResponse> tokenResponse = restTemplate.postForEntity(
            url,
            new HttpEntity<>(body, headers),
            TokenResponse.class
        );

        TokenResponse tokens = tokenResponse.getBody();
        if (tokens == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        // リフレッシュトークンをHttpOnly Cookieに保存（7日間有効）
        if (tokens.getRefreshToken() != null) {
            SecurityUtils.setSecureHttpOnlyCookie(response, "refresh_token", 
                tokens.getRefreshToken(), 7 * 24 * 60 * 60);
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
            HttpServletResponse response) {
        
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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
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
        ResponseEntity<TokenResponse> tokenResponse = restTemplate.postForEntity(
            url,
            new HttpEntity<>(body, headers),
            TokenResponse.class
        );

        TokenResponse tokens = tokenResponse.getBody();
        if (tokens == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        // 新しいリフレッシュトークンをCookieに保存（存在する場合）
        if (tokens.getRefreshToken() != null) {
            SecurityUtils.setSecureHttpOnlyCookie(response, "refresh_token", 
                tokens.getRefreshToken(), 7 * 24 * 60 * 60);
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
