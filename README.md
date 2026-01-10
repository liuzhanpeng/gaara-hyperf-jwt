# Gaara Hyperf JWT Authentication 

基于Gaara Hyperf认证框架的JWT认证扩展包，支持Refresh Token机制。

## Installation

```bash
composer require lzpeng/gaara-hyperf-jwt
```

## Usage

通过配置就可以使用 JWT 认证器进行用户认证。

### Configuration Example

```php
return [
    'guards' => [
        'example' => [
            'matcher' => [ 
                // 具体配置参考 Gaara Hyperf 认证框架文档
            ],
            'user_provider' => [
                // 具体配置参考 Gaara Hyperf 认证框架文档
            ],
            'authenticators' => [
                'json_login' => [ // 需配置合登录认证器使用
                    'check_path' => '/user/check_login', 
                    'success_handler' => [ 
                        'class' => GaaraHyperf\JWT\JWTResponseHandler::class, // 内置的 JWT 响应处理器
                        'params' => [
                            'access_token_manager' => 'default', // 关联 services.jwt_access_token_managers 下的配置; 与认证器共享同一个 Access Token 管理器
                            'refresh_token_manager' => 'default', // 关联 services.jwt_refresh_token_managers 下的配置; 与认证器共享同一个 Refresh Token 管理器
                            // 'refresh_token_response_type' => 'body', // 响应类型; 可选值：body|cookie，默认：body
                            // 'response_template' => '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#"}', // refresh_token_response_type=='bodhy'时生效；可选，自定义响应模板，支持 #ACCESS_TOKEN#、#EXPIRES_IN#、#REFRESH_TOKEN# 占位符
                            // 'refresh_token_cookie_param_name' => 'refresh_token', // 可选; refresh_token 参数名，默认：refresh_token
                            // 'refresh_token_cookie_path' => '/', // refresh_token_response_type=='cookie' 时生效，Cookie 路径，默认：/
                            // 'refresh_token_cookie_domain' => null, // refresh_token_response_type=='cookie' 时生效，Cookie 域名，默认：null
                            // 'refresh_token_cookie_secure' => true, // refresh_token_response_type=='cookie' 时生效，Cookie 是否仅通过 HTTPS 传输，默认：true
                            // 'refresh_token_cookie_samesite' => 'lax', // refresh_token_response_type=='cookie' 时生效，Cookie SameSite 属性，默认：lax, 可选值：lax|strict
                        ],
                    ],
                ],
                'jwt' => [
                    'access_token_manager' => 'default', // 关联 services.jwt_access_token_managers 下的配置
                    // 'access_token_extractor' => [ // 可选，默认从 Authorization Header 中提取 Bearer Token
                    //     'type' => 'header',
                    //     'param_name' => 'Authorization',
                    //     'param_type' => 'Bearer',
                    // ],
                    'refresh_path' => '/user/refresh-token', // 必须; 刷新 Token 的请求路径
                    'refresh_token_manager' => 'default', // 关联 services.jwt_refresh_token_managers 下的配置
                    // 'refresh_token_extractor' => [ // 可选，默认从请求体中提取 refresh_token
                    //     'type' => 'body', // 可选值：body|cookie
                    //     'param_name' => 'refresh_token', // refresh_token 参数名
                    // ],
                ],
            ]
        ]
    ],
    'services' => [
        'jwt_access_token_managers' => [
            'default' => [
                // 'type' => 'default', // 可选，默认值: default; 目前仅支持 default 和 custom 两种类型
                // 'algo' => 'HS512', // 可选；默认：HS512; 签名算法参考: https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
                'secret_key' => 'your-secret', // 必须; 对称算法密钥 或 非对称算法私钥
                // 'public_key' => '', // algo为非对称算法时必须；非对称算法公钥
                // 'passphrase' => '', // algo为非对称算法时可选; 私钥密码（如果有的话）
                // 'expires_in' => 600, // 可选；Access Token 有效期，单位：秒； 默认：600秒（10分钟）; 建议设置为5-10分钟
                // 'leeway' => 5, // 可选; 允许的时间偏差，单位：秒; 默认: null
                // 'iss' => 'xxx', // 可选；Issuer 声明
                // 'aud' => 'xxx-app', // 可选；Audience 声明; 如果需要区分不同应用，可设置此值
            ],
        ],
        // 'jwt_refresh_token_managers' => [
            // 'default' => [ // 这里内置的 refresh token 管理器; 可根据需要自修改参数
            //     'type' => 'default', // 可选，默认值: default; 目前仅支持 default 和 custom 两种类型
            //     'prefix' => 'default', // 可选; refresh token缓存前缀，默认：default； 如果存在多个管理器，需设置不同的前缀以区分
            //     'expires_in' => 60 * 60 * 24 * 14, // 可选； Refresh Token 有效期，单位：秒； 默认：14天
            //     'single_session' => false, // 可选；是否启用单会话模式；默认：false；启用后，同一用户只能存在一个有效的 Refresh Token，登录会使之前的 Refresh Token 失效
            //     'refresh_token_length' => 64, // 可选；Refresh Token 字符串长度；默认：64
            // ],
        // ],
    ]
];
```
