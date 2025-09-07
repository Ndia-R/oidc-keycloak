package com.example.spa_gateway.util;

import java.security.SecureRandom;
import java.util.Base64;

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
}