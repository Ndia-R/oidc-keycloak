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
├── SpaGatewayApplication.java     # メインのSpring Bootアプリケーション
├── controller/
│   └── AuthController.java       # 認証RESTエンドポイント
├── service/
│   └── AuthService.java          # 認証ビジネスロジック
└── dto/
    ├── LoginRequest.java         # ログインリクエスト用ペイロード
    └── TokenResponse.java        # トークンレスポンス構造
```

### 認証フロー
セキュアなトークンベース認証パターンを実装：

1. **ログインエンドポイント** (`POST /auth/login`): メール/パスワードを受け取り、Keycloakで認証、リフレッシュトークンをHttpOnly Cookieに保存し、アクセストークンをJSONで返却
2. **リフレッシュエンドポイント** (`POST /auth/refresh`): Cookieのリフレッシュトークンを使用して新しいアクセストークンを取得
3. **ログアウトエンドポイント** (`POST /auth/logout`): リフレッシュトークンCookieをクリア

### 主要なセキュリティ機能
- リフレッシュトークン保存用HttpOnly Cookie
- HTTPS環境向けSecureフラグ有効化
- `/auth`パスへのCookieスコープ制限
- 自動トークン有効期限管理

## 設定

### Keycloak統合
- **Keycloak URL**: http://localhost:8180
- **レルム**: spa-realm
- **クライアントID**: spa-gateway
- **管理者認証情報**: admin/admin（開発環境のみ）

レルム設定は`realm-export.json`からコンテナ起動時にインポートされます。

### アプリケーション設定
`application.yml`のOAuth2クライアント設定は現在コメントアウトされています。アプリケーションは`AuthService`クラス経由でKeycloakトークンエンドポイントと直接統合します。

## 開発メモ

### パッケージ命名
Javaのパッケージ命名制約により、本来意図していた`spa-gateway`ではなく`spa_gateway`（アンダースコア）を使用しています。

### サービス実装
`AuthService`は現在プレースホルダー実装です。本番環境では、これらのメソッドはKeycloakのトークンエンドポイントへの実際のHTTP呼び出しを行う必要があります。

### フロントエンド統合
`http://localhost:5173`で動作するフロントエンドアプリケーション（典型的なVite開発サーバーポート）との連携用に設定されています。