# CLAUDE.md

このファイルは、Claude Code (claude.ai/code) がこのリポジトリでコードを操作する際のガイダンスを提供します。

# 重要

基本的なやりとりは日本語でおこなってください。

## プロジェクト概要

OAuth2/Keycloak統合によるSPAゲートウェイとして機能するSpring Boot 3.5.5アプリケーションです。Single Page Application向けのバックエンド認証サービスとして動作し、セキュアなCookieベースのリフレッシュトークン管理を行います。

**主要技術:**
- Java 17 + Spring Boot 3.5.5
- Spring Security + OAuth2 Client
- Lombok（ボイラープレートコード削減）
- Keycloak（ID管理）
- Docker コンテナ化

## 開発コマンド

### ビルドと実行
```bash
# プロジェクトのクリーンとビルド
./gradlew clean build

# アプリケーション実行（開発モード）
./gradlew bootRun

# テスト実行
./gradlew test

# 単一テストクラス実行
./gradlew test --tests "com.example.spa_gateway.SpaGatewayApplicationTests"
```

### Docker環境
```bash
# Keycloakと開発環境の開始
docker-compose up -d

# ログ確認
docker-compose logs -f spa-gateway
docker-compose logs -f keycloak

# サービス停止
docker-compose down
```

## アーキテクチャ

### パッケージ構造
```
com.example.spa_gateway/
├── SpaGatewayApplication.java           # メインのSpring Bootアプリケーション
├── controller/
│   ├── AuthController.java             # 認証RESTエンドポイント（従来）
│   └── OidcAuthController.java         # OIDC認証エンドポイント（メイン）
├── service/
│   ├── AuthService.java                # 認証ビジネスロジック
│   └── OidcSessionService.java         # OIDCセッション管理
├── util/
│   └── SecurityUtils.java              # セキュリティユーティリティ
├── config/
│   └── SecurityConfig.java             # Spring Security設定
└── dto/
    ├── LoginRequest.java               # ログインリクエスト用ペイロード
    ├── TokenResponse.java              # Keycloakトークンレスポンス
    └── AccessTokenResponse.java        # クライアント向けレスポンス
```

### 認証フロー
OIDC Authorization Code Flow + PKCEによるセキュアな認証を実装：

1. **ログイン開始** (`GET /auth/login`): 
   - state、nonce、PKCE（code_verifier/challenge）を生成してセッションに保存
   - Keycloak認証URLにリダイレクト
   
2. **認証コールバック** (`GET /auth/callback`):
   - stateパラメータでCSRF攻撃を防止
   - code_verifierでPKCE検証を実行
   - 認可コードをアクセス・リフレッシュトークンに交換
   - リフレッシュトークンをHttpOnly Cookieに保存
   - アクセストークンのみJSONで返却
   
3. **トークンリフレッシュ** (`POST /auth/refresh`):
   - Cookieからリフレッシュトークンを取得
   - 新しいアクセストークンを取得・返却
   - 新しいリフレッシュトークンでCookieを更新
   
4. **ログアウト** (`POST /auth/logout`): 
   - リフレッシュトークンCookieを削除

### 主要なセキュリティ機能
- **OIDC準拠**: OpenID Connect Authorization Code Flowの完全実装
- **PKCE**: Proof Key for Code Exchange による認可コード横取り攻撃対策
- **state パラメータ**: CSRF攻撃防止
- **nonce パラメータ**: リプレイ攻撃防止（IDトークン検証用）
- **HttpOnly Cookie**: XSS攻撃からリフレッシュトークンを保護
- **Secure フラグ**: HTTPS環境でのみCookie送信
- **Cookie スコープ制限**: `/auth`パスでのみ有効
- **自動セッション管理**: セキュリティパラメータの適切な保存・削除

## 設定

### Keycloak統合
- **Keycloak URL**: http://localhost:8180
- **レルム**: spa-realm
- **クライアントID**: spa-gateway
- **管理者認証情報**: admin/admin（開発環境のみ）

レルム設定は`realm-export.json`からコンテナ起動時にインポートされます。

### アプリケーション設定
`application.yml`のOAuth2クライアント設定は現在コメントアウトされています。アプリケーションは`OidcAuthController`経由でKeycloakと直接統合し、OIDC準拠の認証フローを実装しています。

主要な設定項目：
- `keycloak.auth-server-url`: ブラウザ向けKeycloak URL
- `keycloak.auth-server-url-on-docker`: サーバー内部通信用URL
- `keycloak.realm`: 使用するKeycloakレルム
- `keycloak.client-id`: OAuth2クライアントID
- `keycloak.client-secret`: OAuth2クライアントシークレット
- `app.redirect-uri`: 認証後のリダイレクトURI

## 開発メモ

### パッケージ命名
Javaのパッケージ命名制約により、本来意図していた`spa-gateway`ではなく`spa_gateway`（アンダースコア）を使用しています。

### 実装状況
- **OidcAuthController**: 完全なOIDC Authorization Code Flow + PKCE実装済み
- **AuthService**: プレースホルダー実装（従来の認証方式用）
- **SecurityUtils**: セキュリティ関連のユーティリティ機能完備
- **OidcSessionService**: セッション管理とセキュリティパラメータ検証機能実装済み

### 今後の拡張予定
- IDトークンの検証とnonce検証機能
- Spring Securityとの統合
- カスタム認証プロバイダーの実装

### フロントエンド統合
`http://localhost:5173`で動作するフロントエンドアプリケーション（典型的なVite開発サーバーポート）との連携用に設定されています。