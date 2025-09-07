package com.example.spa_gateway.exception;

public class OidcAuthenticationException extends RuntimeException {
    private final String errorCode;

    public OidcAuthenticationException(String message) {
        super(message);
        this.errorCode = "AUTHENTICATION_FAILED";
    }

    public OidcAuthenticationException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public OidcAuthenticationException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "AUTHENTICATION_FAILED";
    }

    public OidcAuthenticationException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}