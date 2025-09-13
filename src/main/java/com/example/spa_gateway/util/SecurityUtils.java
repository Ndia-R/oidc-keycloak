package com.example.spa_gateway.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import com.example.spa_gateway.dto.AccessTokenResponse;
import com.example.spa_gateway.dto.TokenResponse;

public class SecurityUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateSecureRandomString(int length) {
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public static String generateState() {
        return generateSecureRandomString(32);
    }

    public static String generateNonce() {
        return generateSecureRandomString(32);
    }

    /**
     * PKCE用のcode_verifierを生成します
     * RFC 7636に従い43-128文字のURL-safeな文字列を生成
     */
    public static String generateCodeVerifier() {
        return generateSecureRandomString(32); // 43文字になる
    }

    /**
     * code_verifierからcode_challengeを生成します
     * SHA256ハッシュ化してBase64 URL-safeエンコード
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256アルゴリズムが利用できません", e);
        }
    }

    /**
     * セキュアなHttpOnly Cookieを設定します
     */
    public static void setSecureHttpOnlyCookie(HttpServletResponse response, String name, String value, int maxAge, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // HTTPS環境でのみ送信
        cookie.setPath(path);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    /**
     * Cookieを削除します
     */
    public static void deleteCookie(HttpServletResponse response, String name, String path) {
        Cookie cookie = new Cookie(name, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(path);
        cookie.setMaxAge(0); // 即座に削除
        response.addCookie(cookie);
    }

    /**
     * リフレッシュトークンをHttpOnly Cookieに保存します
     */
    public static void saveRefreshTokenToCookie(HttpServletResponse response, String tokenName, String refreshToken, int maxAge, String path) {
        if (refreshToken != null) {
            setSecureHttpOnlyCookie(response, tokenName, refreshToken, maxAge, path);
        }
    }

    /**
     * TokenResponseからAccessTokenResponseを作成します
     */
    public static AccessTokenResponse createAccessTokenResponse(TokenResponse tokens) {
        return new AccessTokenResponse(
            tokens.getAccessToken(),
            tokens.getExpiresIn(),
            tokens.getTokenType(),
            tokens.getScope()
        );
    }
}