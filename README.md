# Gaara Hyperf JWT

Gaara Hyperf JWT 是一个面向 API 场景的 JWT 认证扩展，用于在 Gaara Hyperf 中快速接入 Access Token 与 Refresh Token 机制。它内置 JWT 认证器、登录成功处理器、刷新令牌管理与可自定义响应能力，适合需要无状态认证、短期访问令牌和安全刷新流程的项目使用。

## 安装

```bash
composer require lzpeng/gaara-hyperf-jwt
```

## 快速开始

配置示例：

```php
<?php

use GaaraHyperf\JWT\JWTSuccessHandler;

return [
    'guards' => [
        'api' => [
            'matcher' => [
                'pattern' => '^/api',
                'logout_path' => '/api/logout', // 如需触发 LogoutEvent，需配置该路径
            ],
            'user_provider' => [
                // 参考 gaara-hyperf 文档
            ],
            'authenticators' => [
                'json_login' => [ // 搭配其它认证器使用，负责处理登录请求
                    'check_path' => '/api/login',
                    'success_handler' => [
                        'class' => JWTSuccessHandler::class,
                        'params' => [
                            'jwt_manager' => 'default', // 关联 services.jwt_managers 下的配置; 需跟jwt 认证器使用同一个 JWT Manager
                        ],
                    ],
                ],
                'jwt' => [
                    'jwt_manager' => 'default',
                ],
            ],
        ],
    ],
    'services' => [
        'jwt_managers' => [
            'default' => [
                'secret_key' => 'your-secret', // 必须; 对称算法密钥 或 非对称算法私钥
                // 'prefix' => 'default', // 可选；Refresh Token 缓存前缀，默认：default
                // 详细参数配置参考下文核心配置章节
            ],
        ],
    ],
];
```

默认流程：

1. 登录成功后由 `JWTSuccessHandler` 调用对应的 JWT Manager 签发 Token。
2. 后续请求通过 `Authorization: Bearer <token>` 携带 Access Token。
3. Access Token 过期后，请求配置的 `refresh_token_path` 获取新 Token。

默认 body 响应示例：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "access_token": "jwt-access-token",
    "expires_in": 600,
    "refresh_token": "plain-refresh-token",
    "refresh_expires_in": 1209600
  }
}
```

## 核心配置

### `authenticators.jwt`

```php
'jwt' => [
    'jwt_manager' => 'default',
],
```

- `jwt_manager` 用于关联 `services.jwt_managers` 中的具体配置。
- Access Token 提取、Refresh Token 提取、刷新路径与响应格式，统一在对应的 JWT Manager 配置中定义。

### `JWTSuccessHandler`

```php
'success_handler' => [
    'class' => GaaraHyperf\JWT\JWTSuccessHandler::class,
    'params' => [
        'jwt_manager' => 'default',
    ],
],
```

- `success_handler` 与 `authenticators.jwt` 建议使用同一个 `jwt_manager`。
- 登录成功后，`JWTSuccessHandler` 会自动签发 Access Token，并在启用时同时签发 Refresh Token。
- 如果用户实现了 `JWTCustomClaimAwareUserInterface`，其自定义 Claims 会一并写入 Access Token。

### `services.jwt_managers`

```php
'jwt_managers' => [
    'default' => [
        // 'type' => 'default', // 可选，默认值: default; 目前仅支持 default 和 custom 两种类型
        // 'algo' => 'HS512', // 可选；默认：HS512; 签名算法参考: https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
        'secret_key' => 'your-secret', // 必须; 对称算法密钥 或 非对称算法私钥
        // 'public_key' => '', // algo为非对称算法时必须；非对称算法公钥
        // 'passphrase' => '', // algo为非对称算法时可选; 私钥密码（如果有的话）
        // 'leeway' => 5, // 可选; 允许的时间偏差，单位：秒; 默认: null
        // 'iss' => 'xxx', // 可选；Issuer 声明
        // 'aud' => 'xxx-app', // 可选；Audience 声明; 如果需要区分不同应用，可设置此值
        // 'ttl' => 600, // 可选；Access Token 有效期，单位：秒； 默认：600秒（10分钟）; 建议设置为5-10分钟
        // 'access_token_extractor' => [ // 可选，默认从 Authorization Header 中提取 Bearer Token
        //     'type' => 'header',
        //     'field' => 'Authorization',
        //     'scheme' => 'Bearer',
        // ],
        // 'refresh_token_enabled' => true, // 可选；是否启用 Refresh Token 机制，默认：true
        // 'refresh_token_path' => '/user/refresh-token', // refresh_token_enabled 为 true 时必须；刷新 Token 的请求路径
        // 'refresh_token_prefix' => 'default', // 可选; refresh token缓存前缀，默认：default； 如果存在多个管理器，需设置不同的前缀以区分
        // 'refresh_token_ttl' => 60 * 60 * 24 * 14, // 可选；Refresh Token 有效期，单位：秒；默认：60 * 60 * 24 * 14
        // 'refresh_token_single_session' => false, // 可选；是否启用单会话模式；默认：false；启用后，同一用户只能存在一个有效的 Refresh Token，登录会使之前的 Refresh Token 失效
        // 'refresh_token_length' => 64, // 可选；Refresh Token 字符串长度；默认：64
        // 'refresh_token_extractor' => [ // 可选，默认从请求体中提取 refresh_token
        //     'type' => 'body', // 可选值：body|cookie
        //     'field' => 'refresh_token', // refresh_token 参数名
        // ],
        // 'token_responder' => [
        //     'type' => 'body', // 支持 body（以json响应体返回）, cookie(access_token信息还是以json响应体返回, refresh_token以cookie响应), custom; 默认body
        //     'template' => '{"code": 0, "message": "success", "data": {"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#", "refresh_expires_in": #REFRESH_EXPIRES_IN#}}',
        //     'refresh_token_cookie_name' => 'refresh_token', // 可选; refresh_token 参数名，默认：refresh_token
        //     'refresh_token_cookie_path' => '/', // refresh_token_response_type=='cookie' 时生效，Cookie 路径，默认：/
        //     'refresh_token_cookie_domain' => null, // refresh_token_response_type=='cookie' 时生效，Cookie 域名，默认：null
        //     'refresh_token_cookie_secure' => true, // refresh_token_response_type=='cookie' 时生效，Cookie 是否仅通过 HTTPS 传输，默认：true
        //     'refresh_token_cookie_http_only' => true, // refresh_token_response_type=='cookie' 时生效，Cookie 是否为 HttpOnly，默认：true
        //     'refresh_token_cookie_samesite' => 'lax', // refresh_token_response_type=='cookie' 时生效，Cookie SameSite 属性，默认：lax, 可选值：lax|strict
        // ]
    ],
],
```

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

### 自定义 Responder

如果你需要完全自定义登录成功后的响应结构，可以为 `token_responder` 指定自定义实现：

```php
'token_responder' => [
    'type' => 'custom',
    'class' => App\Auth\CustomJWTokenResponder::class,
    'params' => [
        'foo' => 'bar',
    ],
],
```

- 自定义响应器必须实现 `GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface`。
- 如果只需要改返回 JSON 结构，优先使用 `template` 即可，无需自定义类。

### 刷新与登出

- 刷新请求命中 `refresh_token_path` 时，旧 Refresh Token 会被撤销，再签发新 Token。
- 开启 Refresh Token 后，会自动注册登出监听器。
- 登出撤销仅在 `POST` 请求中生效。

### `JWTRevokeLogoutListener` 使用说明

`JWTRevokeLogoutListener` 会在启用 JWT 认证器后自动注册，无需手动绑定。它会监听登出事件，并在满足条件时撤销当前请求携带的 Refresh Token。

要触发 `LogoutEvent`，除了启用 JWT 认证外，还需要在 Guard 的 `matcher` 中配置 `logout_path`。只有当请求命中该路径时，Gaara Hyperf 才会将其识别为登出请求并派发登出事件。

生效条件如下：

- 已启用 Refresh Token 机制；
- Guard 的 `matcher` 已配置 `logout_path`；
- 当前请求路径命中 `logout_path`；
- 请求方法为 `POST`；
- 请求中能够被 `refresh_token_extractor` 正常提取到 Refresh Token。

典型场景是用户调用登出接口时，服务端同步废弃当前 Refresh Token，避免退出后旧 Token 继续用于刷新。

如果你使用的是请求体提取方式，确保登出请求中也携带对应的 `refresh_token` 字段；如果使用 Cookie 提取方式，则需要保证请求会附带相应 Cookie。

## 常见问题

### 缺少 `refresh_token_path`

```text
Refresh path must be provided when refresh token is enabled.
```

开启 Refresh Token 后，必须在对应的 `jwt_manager` 配置中设置 `refresh_token_path`。

### Token 无效或未携带

```text
Invalid access token
Invalid refresh token
```

- 检查 `Authorization: Bearer <token>` 是否正确。
- 如果使用 Cookie 模式，记得把 `refresh_token_extractor` 改成 `cookie`。
- 检查 `jwt_manager`、`secret_key`、`iss`、`aud` 与签发时是否一致。

### Refresh Token 无效

```text
Invalid refresh token
```

常见原因：已过期、已被刷新撤销、或 `single_session` 导致旧 Token 失效。

### 自定义模板不是合法 JSON

```text
Response template must be a valid JSON string
```

`template` 必须是合法 JSON 字符串。
