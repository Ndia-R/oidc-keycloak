package com.example.spa_gateway.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.WebRequest;

import com.example.spa_gateway.dto.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(OidcAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleOidcAuthenticationException(
        OidcAuthenticationException ex,
        WebRequest request
    ) {

        logger.error("OIDC認証エラー: {}", ex.getMessage(), ex);

        ErrorResponse error = new ErrorResponse(
            ex.getErrorCode(),
            ex.getMessage(),
            HttpStatus.UNAUTHORIZED.value(),
            request.getDescription(false).replace("uri=", "")
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<ErrorResponse> handleHttpClientErrorException(
        HttpClientErrorException ex,
        WebRequest request
    ) {

        logger.error("HTTPクライアントエラー: {} - {}", ex.getStatusCode(), ex.getMessage(), ex);

        String errorCode;
        String message;
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());

        switch (ex.getStatusCode().value()) {
        case 400:
            errorCode = "INVALID_REQUEST";
            message = "無効なリクエストです";
            break;
        case 401:
            errorCode = "UNAUTHORIZED";
            message = "認証に失敗しました";
            break;
        case 403:
            errorCode = "FORBIDDEN";
            message = "アクセスが拒否されました";
            break;
        default:
            errorCode = "CLIENT_ERROR";
            message = "リクエストの処理中にエラーが発生しました";
        }

        ErrorResponse error = new ErrorResponse(
            errorCode,
            message,
            status.value(),
            request.getDescription(false).replace("uri=", "")
        );

        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<ErrorResponse> handleResourceAccessException(
        ResourceAccessException ex,
        WebRequest request
    ) {

        logger.error("リソースアクセスエラー: {}", ex.getMessage(), ex);

        ErrorResponse error = new ErrorResponse(
            "SERVICE_UNAVAILABLE",
            "認証サービスに接続できません",
            HttpStatus.SERVICE_UNAVAILABLE.value(),
            request.getDescription(false).replace("uri=", "")
        );

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(error);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
        Exception ex,
        WebRequest request
    ) {

        logger.error("予期しないエラーが発生しました: {}", ex.getMessage(), ex);

        ErrorResponse error = new ErrorResponse(
            "INTERNAL_SERVER_ERROR",
            "内部サーバーエラーが発生しました",
            HttpStatus.INTERNAL_SERVER_ERROR.value(),
            request.getDescription(false).replace("uri=", "")
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}