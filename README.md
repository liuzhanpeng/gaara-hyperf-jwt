# Gaara Hyperf JWT

Gaara Hyperf JWT 是一个面向 API 场景的 JWT 认证扩展包，用于在 Gaara Hyperf 认证体系中接入 Access Token 与 Refresh Token 机制。它提供开箱即用的 JWT 认证器、登录成功响应处理器，以及可扩展的 Access Token 和 Refresh Token 管理能力。本文档仅说明本扩展包的接入与配置方式。

## 安装

```bash
composer require lzpeng/gaara-hyperf-jwt
```

## 快速开始

最小配置示例：

```php
<?php

use GaaraHyperf\JWT\JWTResponseHandler;

return [
    'guards' => [
        'api' => [
            'matcher' => [
                // 参考 gaara-hyperf 文档
            ],
            'user_provider' => [
                // 参考 gaara-hyperf 文档
            ],
            'authenticators' => [
                'json_login' => [
                    'check_path' => '/api/login',
                    'success_handler' => [
                        'class' => JWTResponseHandler::class,
                        'params' => [
                            'access_token_manager' => 'default',
                            'refresh_token_manager' => 'default',
                            'refresh_token_enabled' => true,
                        ],
                    ],
                ],
                'jwt' => [
                    'access_token_manager' => 'default',
                    'refresh_token_enabled' => true,
                    'refresh_path' => '/api/refresh-token',
                    'refresh_token_manager' => 'default',
                ],
            ],
        ],
    ],
    'services' => [
        'jwt_access_token_managers' => [
            'default' => [
                'secret_key' => 'your-secret-key',
            ],
        ],
        'jwt_refresh_token_managers' => [
            'default' => [
                'prefix' => 'default',
            ],
        ],
    ],
];
```

默认流程：

1. 登录成功后由 `JWTResponseHandler` 签发 Token。
2. 后续请求通过 `Authorization: Bearer <token>` 携带 Access Token。
3. Access Token 过期后，请求 `POST /api/refresh-token` 获取新 Token。

默认登录响应：

```json
{
  "access_token": "jwt-access-token",
  "expires_in": 600,
  "refresh_token": "plain-refresh-token"
}
```

## 核心配置

### `authenticators.jwt`

```php
'jwt' => [
    'access_token_manager' => 'default',
    'refresh_token_enabled' => true,
    'refresh_path' => '/api/refresh-token',
    'refresh_token_manager' => 'default',
    'access_token_extractor' => [
        'type' => 'header',
        'field' => 'Authorization',
        'scheme' => 'Bearer',
    ],
    'refresh_token_extractor' => [
        'type' => 'body',
        'field' => 'refresh_token',
    ],
],
```

- `refresh_path` 在 `refresh_token_enabled=true` 时必填。
- 默认从 `Authorization` Header 提取 Access Token。
- 默认从请求体字段 `refresh_token` 提取 Refresh Token。

### `JWTResponseHandler`

```php
'success_handler' => [
    'class' => GaaraHyperf\JWT\JWTResponseHandler::class,
    'params' => [
        'access_token_manager' => 'default',
        'refresh_token_manager' => 'default',
        'refresh_token_enabled' => true,
        'refresh_token_response_type' => 'body',
    ],
],
```

- `refresh_token_response_type` 支持 `body` 和 `cookie`，默认 `body`。
- `cookie` 模式下，Refresh Token 写入 Cookie，响应体只返回 `access_token` 和 `expires_in`。
- `response_template` 支持 `#ACCESS_TOKEN#`、`#EXPIRES_IN#`、`#REFRESH_TOKEN#` 占位符，且必须是合法 JSON。

### `services.jwt_access_token_managers`

```php
'jwt_access_token_managers' => [
    'default' => [
        'type' => 'default',
        'algo' => 'HS512',
        'secret_key' => 'your-secret-key',
        'ttl' => 600,
        'leeway' => null,
        'iss' => 'gaara-hyperf-jwt',
        'aud' => '',
    ],
],
```

- `secret_key` 必填。
- 默认算法为 `HS512`，默认有效期为 `600` 秒。
- 支持非对称算法，此时需要额外提供 `public_key`，可选 `passphrase`。

### `services.jwt_refresh_token_managers`

```php
'jwt_refresh_token_managers' => [
    'default' => [
        'type' => 'default',
        'prefix' => 'default',
        'ttl' => 60 * 60 * 24 * 14,
        'single_session' => false,
        'refresh_token_length' => 64,
    ],
],
```

- 默认有效期为 14 天。
- `single_session=true` 时，同一用户只保留一个有效 Refresh Token。
- `refresh_token_length` 建议不小于 `32`。

## 高级能力

### 自定义 Claims

用户对象实现 `GaaraHyperf\JWT\JWTCustomClaimAwareUserInterface` 后，`getJWTCustomClaims()` 的返回值会注入到 Access Token：

```php
use GaaraHyperf\JWT\JWTCustomClaimAwareUserInterface;
use GaaraHyperf\User\UserInterface;

class User implements UserInterface, JWTCustomClaimAwareUserInterface
{
    public function getIdentifier(): string
    {
        return 'user-1';
    }

    public function getJWTCustomClaims(): array
    {
        return [
            'role' => 'admin',
            'tenant' => 'acme',
        ];
    }
}
```

### 自定义 Manager

支持通过 `type => 'custom'` 接入自定义实现：

```php
'jwt_access_token_managers' => [
    'custom_access' => [
        'type' => 'custom',
        'class' => App\Auth\CustomAccessTokenManager::class,
        'params' => [
            'ttl' => 1800,
        ],
    ],
],
```

- Access Token Manager 必须实现 `GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface`
- Refresh Token Manager 必须实现 `GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface`

### 刷新与登出

- 刷新请求命中 `refresh_path` 时，旧 Refresh Token 会被撤销，再签发新 Token。
- 开启 Refresh Token 后，会自动注册登出监听器。
- 登出撤销仅在 `POST` 请求中生效。

## 常见问题

### 缺少 `refresh_path`

```text
The "refresh_path" option is required when refresh_token_enabled is true.
```

开启 Refresh Token 后，必须在 `authenticators.jwt` 中配置 `refresh_path`。

### 请求中没有 Token

```text
No access token found in the request
No refresh token found in the request
```

- 检查 `Authorization: Bearer <token>` 是否正确。
- 如果使用 Cookie 模式，记得把 `refresh_token_extractor` 改成 `cookie`。

### Refresh Token 无效

```text
Invalid refresh token
```

常见原因：已过期、已被刷新撤销、或 `single_session` 导致旧 Token 失效。

### 自定义模板不是合法 JSON

```text
Response template must be a valid JSON string
```

`response_template` 必须是合法 JSON 字符串。
