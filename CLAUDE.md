# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

このファイルは、Claude Code (claude.ai/code) がこのリポジトリでコードを操作する際のガイダンスを提供します。

# 重要

基本的なやりとりは日本語でおこなってください。

## プロジェクト概要

OAuth2/Keycloak統合によるSPAゲートウェイとして機能するSpring Boot 3.5.5アプリケーションです。Single Page Application向けのバックエンド認証サービスとして動作し、セキュアなCookieベースのリフレッシュトークン管理を行います。

**主要技術:**
- Java 17 + Spring Boot 3.5.5
- Spring Security + OAuth2 Client
- Spring WebFlux（WebClientによるHTTP通信）
- Lombok（ボイラープレートコード削減）
- Keycloak（ID管理）
- Auth0 JWT Library（IDトークン検証）
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

# Dockerコンテナ内でビルド・実行
docker exec -it <container-name> ./gradlew bootRun
```

## アーキテクチャ

### パッケージ構造
```
com.example.spa_gateway/
├── SpaGatewayApplication.java           # メインのSpring Bootアプリケーション
├── controller/
│   ├── AuthController.java             # メール・パスワード認証エンドポイント
│   └── OidcController.java             # OIDC認証エンドポイント（メイン）
├── service/
│   ├── AuthService.java                # メール・パスワード認証ビジネスロジック
│   ├── OidcService.java                # OIDC認証ビジネスロジック
│   └── OidcSessionService.java         # OIDCセッション管理
├── exception/
│   ├── GlobalExceptionHandler.java     # 統一例外処理
│   └── OidcAuthenticationException.java # OIDC認証専用例外
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

#### 1. OIDC Authorization Code Flow + PKCE（主要フロー）
完全なOIDC 1.0準拠認証を実装：

1. **ログイン開始** (`GET /auth/login`): 
   - state、nonce、PKCE（code_verifier/challenge）を生成してセッションに保存
   - Keycloak認証URLにリダイレクト
   
2. **認証コールバック** (`GET /auth/callback`):
   - stateパラメータでCSRF攻撃を防止
   - code_verifierでPKCE検証を実行
   - 認可コードをアクセス・リフレッシュトークンに交換
   - **IDトークン検証**: JWT署名検証、nonce検証、発行者・受信者検証
   - リフレッシュトークンをHttpOnly Cookieに保存
   - アクセストークンのみJSONで返却
   
3. **トークンリフレッシュ** (`POST /auth/refresh`):
   - Cookieからリフレッシュトークンを取得
   - 新しいアクセストークンを取得・返却
   - 新しいリフレッシュトークンでCookieを更新
   
4. **ログアウト** (`POST /auth/logout`): 
   - リフレッシュトークンCookieを削除

#### 2. メール・パスワード認証フロー（補助フロー）
従来のResource Owner Password Credentialsフローを実装：

1. **ログイン** (`POST /auth-with-password/login`):
   - メール・パスワードで直接Keycloakに認証
   - リフレッシュトークンをHttpOnly Cookieに保存
   
2. **リフレッシュ・ログアウト**: OIDCフローと同様

### 主要なセキュリティ機能
- **OIDC 1.0完全準拠**: OpenID Connect Authorization Code Flowの完全実装
- **IDトークン検証**: JWT署名検証、nonce検証、発行者・受信者検証
- **JWKS統合**: Keycloakから動的に公開鍵を取得してJWT署名検証
- **PKCE**: Proof Key for Code Exchange による認可コード横取り攻撃対策
- **state パラメータ**: CSRF攻撃防止
- **nonce パラメータ**: リプレイ攻撃防止（IDトークン検証用）
- **HttpOnly Cookie**: XSS攻撃からリフレッシュトークンを保護
- **Secure フラグ**: HTTPS環境でのみCookie送信
- **Cookie スコープ制限**: `/auth`および`/auth-with-password`パスでのみ有効
- **統一例外処理**: GlobalExceptionHandlerによる一貫したエラーレスポンス
- **自動セッション管理**: セキュリティパラメータの適切な保存・削除

## 設定

### Keycloak統合
- **Keycloak URL**: http://localhost:8180
- **レルム**: spa-realm
- **クライアントID**: spa-gateway
- **管理者認証情報**: admin/admin（開発環境のみ）

レルム設定は`realm-export.json`からコンテナ起動時にインポートされます。

### アプリケーション設定
`application.yml`のOAuth2クライアント設定は現在コメントアウトされています。アプリケーションは`OidcController`経由でKeycloakと直接統合し、OIDC準拠の認証フローを実装しています。

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
- **OidcController**: 完全なOIDC 1.0 Authorization Code Flow + PKCE + IDトークン検証実装済み
- **OidcService**: JWKS統合、JWT署名検証、WebClient使用の完全なOIDCサービス
- **AuthController**: メール・パスワード認証フロー（Resource Owner Password Credentials）
- **AuthService**: WebClient使用のメール・パスワード認証サービス
- **SecurityUtils**: 統一されたCookie管理とレスポンス作成ユーティリティ
- **OidcSessionService**: セッション管理とセキュリティパラメータ検証機能実装済み
- **GlobalExceptionHandler**: OIDC認証例外を含む統一例外処理

### 技術的特徴
- **WebClient採用**: 将来性を考慮してRestTemplateからWebClientに移行済み
- **統一設計**: 両認証フローで共通パターンとSecurityUtilsを使用
- **完全なOIDC準拠**: IDトークン検証、JWT署名検証、JWKS統合を含む
- **エラー処理統一**: 一貫したエラーレスポンス形式

### 今後の拡張予定
- Spring Securityとの統合
- カスタム認証プロバイダーの実装
- トークンイントロスペクション機能

### フロントエンド統合
`http://localhost:5173`で動作するフロントエンドアプリケーション（典型的なVite開発サーバーポート）との連携用に設定されています。

### API エンドポイント

#### OIDC認証（推奨）
- `GET /auth/login` - OIDC認証開始（Keycloakにリダイレクト）
- `GET /auth/callback` - OIDC認証コールバック
- `POST /auth/refresh` - アクセストークンリフレッシュ
- `POST /auth/logout` - ログアウト

#### メール・パスワード認証
- `POST /auth-with-password/login` - メール・パスワードログイン
- `POST /auth-with-password/refresh` - アクセストークンリフレッシュ
- `POST /auth-with-password/logout` - ログアウト

## 重要なファイル
- `realm-export.json`: Keycloakレルム設定ファイル（コンテナ起動時に自動インポート）
- `docker-compose.yml`: 開発環境設定（Keycloak + アプリケーション）
- `build.gradle`: プロジェクト依存関係とビルド設定
- `application.yml`: アプリケーション設定（Keycloak統合情報）