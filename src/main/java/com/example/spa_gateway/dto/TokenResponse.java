package com.example.spa_gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private int expiresIn; // アクセストークンの有効期限（秒）
    private int refreshExpiresIn; // リフレッシュトークンの有効期限（秒）
}
