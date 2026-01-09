# gaara-hyperf-jwt

gaara-hyperf jwt authentication extension

### 配置

```php

return [
    'guards' => [
        'example' => [
            'authenticators' => [
                'json_login' => [
                    'check_path' => '/user/check_login', 
                    'success_handler' => [ 
                        'class' => JWTResponseHandler::class,
                        'params' => [
                            'access_token_manager' => 'default', // 关联 services.jwt_access_token_managers 下的配置
                            'refresh_token_manager' => 'default', // 关联 services.jwt_refresh_token_managers 下的配置
                            // 'refresh_token_response_type' => 'body', // 响应类型; 可选值：body|cookie，默认：body
                            // 'response_template' => '{"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#"}', // refresh_token_response_type=='bodhy'时生效；可选，自定义响应模板，支持 #ACCESS_TOKEN#、#EXPIRES_IN#、#REFRESH_TOKEN# 占位符
                            // 'refresh_token_cookie_name' => 'refresh_token', // refresh_token_response_type=='cookie' 时生效，Cookie 名称，默认：refresh_token
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
                    'refresh_path' => '/auth/refresh', // 必须;刷新 Token 的请求路径
                    // 'refresh_token_manager' => 'default', // 关联 services.jwt_refresh_token_managers 下的配置
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
                'type' => 'default',
                'algo' => 'HS512', // JWT 签名算法; 参考: https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
                'secret_key' => 'your-secret', // 对称算法密钥 或 非对称算法私钥
                // 'public_key' => '', // 非对称算法公钥
                // 'pass_phrase' => '', // 私钥密码（如果有的话）
                'expires_in' => 600, // Access Token 有效期，单位：秒
                // 'leeway' => 5, // 允许的时间偏差，单位：秒
                // 'iss' => 'xxx',
                // 'aud' => 'xxx-app',
            ],
        ],
        'jwt_refresh_token_managers' => [
            'default' => [
                // 'type' => 'default',
                // 'prefix' => 'default',
                // 'expires_in' => 60 * 60 * 24 * 14, // Refresh Token 有效期，单位：秒
            ],
        ],
    ]
];
```
