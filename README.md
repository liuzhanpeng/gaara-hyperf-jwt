# gaara-hyperf-jwt

gaara-hyperf jwt authentication extension

### 配置

```php

return [
    'guards' => [
        'example' => [
            'authenticators' => [
                'json_login' => [
                    'check_path' => '/admin/check_login', 
                    'success_handler' => [ 
                        'class' => JWTResponseHandler::class,
                        'params' => [
                            'token_manager' => 'default',
                        ],
                    ],
                ],
                'jwt' => [
                    'token_manager' => 'default', // 关联 services.jwt_access_token_managers 下的配置
                    // 'token_extractor' => [ // 可选，默认从 Authorization Header 中提取 Bearer Token
                    //     'type' => 'header',
                    //     'param_name' => 'Authorization',
                    //     'param_type' => 'Bearer',
                    // ],
                ],
                // 'jwt_refresh' => [
                //     'refresh_path' => '/auth/refresh',
                //     'revoke_path' => '/auth/refresh/revoke',
                //     'refresh_token_manager' => 'default',
                //     'refresh_token_extractor' => [
                //         'type' => 'cookie',
                //         'param_name' => 'refresh_token',
                //     ],
                // ]
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
                'ttl' => 600, // Access Token 有效期，单位：秒
                // 'leeway' => 0, // 允许的时间偏差，单位：秒
                'iss' => 'gaara',
                'aud' => 'api',
            ],
        ],
    ]
];
```
