# Gaara Hyperf JWT

`gaara-hyperf-jwt` is a JWT authentication extension for [gaara-hyperf](https://github.com/liuzhanpeng/gaara-hyperf), designed for stateless API scenarios. It provides an Access Token / Refresh Token workflow with a built-in `JWTSuccessHandler`, refresh and revocation logic, and fully customisable response formats.

> 中文文档请查看 [README.md](README.md)

## Installation

```bash
composer require lzpeng/gaara-hyperf-jwt
```

> **Prerequisite**: `lzpeng/gaara-hyperf` must already be installed and configured.

## Quick Start

```php
<?php

use GaaraHyperf\JWT\JWTSuccessHandler;

return [
    'guards' => [
        'api' => [
            'matcher' => [
                'pattern' => '^/api',
            ],
            'user_provider' => [
                // see gaara-hyperf docs
            ],
            'authenticators' => [
                'json_login' => [          // handles login requests
                    'check_path'      => '/api/login',
                    'success_handler' => [
                        'class'  => JWTSuccessHandler::class,
                        'params' => [
                            'jwt_manager' => 'default',  // must match the jwt authenticator
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
                'secret_key'            => 'your-secret',
                'refresh_token_enabled' => true,
                'refresh_token_path'    => '/jwt/refresh-token',
                'logout_path'           => '/jwt/logout',
            ],
        ],
    ],
];
```

**Default flow:**

1. On successful login, `JWTSuccessHandler` calls the configured JWT Manager and issues tokens.
2. Subsequent requests carry the Access Token in `Authorization: Bearer <token>`.
3. When the Access Token expires, the client calls `refresh_token_path` to obtain a new pair.

**Default JSON response:**

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

---

## Core Configuration

### `authenticators.jwt`

```php
'jwt' => [
    'jwt_manager' => 'default',
],
```

Associates the JWT authenticator with a named `jwt_manager` entry under `services.jwt_managers`.

### `JWTSuccessHandler`

```php
'success_handler' => [
    'class'  => GaaraHyperf\JWT\JWTSuccessHandler::class,
    'params' => ['jwt_manager' => 'default'],
],
```

Use the **same** `jwt_manager` name for both the authenticator and the success handler. If the user implements `JWTCustomClaimAwareUserInterface`, its custom claims are embedded in the Access Token.

### `services.jwt_managers`

```php
'jwt_managers' => [
    'default' => [
        // 'type'       => 'default',          // optional; 'default' or 'custom'
        // 'algo'       => 'HS512',             // optional; default HS512 — see https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
        'secret_key'    => 'your-secret',       // required; symmetric key or asymmetric private key
        // 'public_key' => '',                  // required for asymmetric algorithms
        // 'passphrase' => '',                  // optional; private-key passphrase
        // 'leeway'     => 5,                   // optional; clock skew tolerance in seconds
        // 'iss'        => 'xxx',               // optional; Issuer claim
        // 'aud'        => 'xxx-app',           // optional; Audience claim
        // 'ttl'        => 600,                 // optional; Access Token TTL in seconds (default 600)
        // 'access_token_extractor' => [
        //     'type'   => 'header',
        //     'field'  => 'Authorization',
        //     'scheme' => 'Bearer',
        // ],
        // 'refresh_token_enabled'        => true,
        // 'refresh_token_path'           => '/user/refresh-token',  // required when refresh enabled
        // 'refresh_token_prefix'         => 'default',
        // 'refresh_token_ttl'            => 1209600,                // 14 days
        // 'refresh_token_single_session' => true,                   // one active refresh token per user
        // 'refresh_token_length'         => 64,
        // 'refresh_token_extractor' => [
        //     'type'  => 'body',   // 'body' or 'cookie'
        //     'field' => 'refresh_token',
        // ],
        // 'token_responder' => [
        //     'type'     => 'body',  // 'body', 'cookie', or 'custom'
        //     'template' => '{"code":0,"message":"success","data":{"access_token":"#ACCESS_TOKEN#","expires_in":#EXPIRES_IN#,"refresh_token":"#REFRESH_TOKEN#","refresh_expires_in":#REFRESH_EXPIRES_IN#}}',
        //     'refresh_token_cookie_name'     => 'refresh_token',
        //     'refresh_token_cookie_path'     => '/',
        //     'refresh_token_cookie_domain'   => null,
        //     'refresh_token_cookie_secure'   => true,
        //     'refresh_token_cookie_http_only'=> true,
        //     'refresh_token_cookie_samesite' => 'lax',
        // ],
    ],
],
```

---

## Advanced

### Custom Claims

Implement `JWTCustomClaimAwareUserInterface` to embed extra claims in the Access Token:

```php
use GaaraHyperf\JWT\JWTCustomClaimAwareUserInterface;
use GaaraHyperf\User\UserInterface;

class User implements UserInterface, JWTCustomClaimAwareUserInterface
{
    public function getIdentifier(): string { return 'user-1'; }

    public function getJWTCustomClaims(): array
    {
        return ['role' => 'admin', 'tenant' => 'acme'];
    }
}
```

### Custom Token Responder

To fully control the login-success response:

```php
'token_responder' => [
    'type'   => 'custom',
    'class'  => App\Auth\CustomJWTokenResponder::class,
    'params' => ['foo' => 'bar'],
],
```

The class must implement `GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface`.  
For simple structure changes, prefer the `template` option — no custom class needed.

### Refresh & Logout

- On a refresh request, the old Refresh Token is revoked before a new pair is issued.
- Enabling Refresh Tokens automatically registers `JWTRevokeLogoutListener`.
- Revocation only fires on `POST` requests matching `logout_path`.

**`JWTRevokeLogoutListener` conditions (all must be true):**

- Refresh Token is enabled.
- `logout_path` is configured and matched.
- Request method is `POST`.
- The Refresh Token can be extracted from the request.

---

## FAQ

**Missing `refresh_token_path`**

```text
Refresh path must be provided when refresh token is enabled.
```

Set `refresh_token_path` in the `jwt_manager` config when Refresh Tokens are enabled.

**Invalid or missing token**

```text
Invalid access token
Invalid refresh token
```

- Verify the `Authorization: Bearer <token>` header.
- For Cookie mode, ensure `refresh_token_extractor` is set to `cookie`.
- Confirm `secret_key`, `iss`, and `aud` match between issuance and verification.

**Expired or revoked Refresh Token**

```text
Invalid refresh token
```

Common causes: expired, already rotated, or invalidated by `single_session` mode.

**Template is not valid JSON**

```text
Response template must be a valid JSON string
```

The `template` value must be a valid JSON string with the placeholder tokens.
