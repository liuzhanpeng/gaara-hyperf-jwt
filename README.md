# gaara-hyperf-jwt
gaara-hyperf jwt authentication extension

### 配置

```php

return [
    'guards' => [
        'example' => [
            'authenticators' => [
                'jwt' => [
                    'token_manager' => 'default',
                    'blacklist_enabled' => true,
                ],
                'jwt_refresh' => [
                    'refresh_token_manager' => 'default',
                ]
            ]
        ]
    ],
    'services' => [
        'jwt_token_manager' => [
            'default' => [
                'algo' => 'HS512', // JWT 签名算法; 参考: https://lcobucci-jwt.readthedocs.io/en/latest/supported-algorithms/
                'secret_key' => 'your-secret', // 对称算法密钥 或 非对称算法私钥
                // 'public_key' => '', // 非对称算法公钥
                // 'pass_phrase' => '', // 私钥密码（如果有的话）
                'ttl' => 1200, // Access Token 有效期，单位：秒
                // 'leeway' => 0, // 允许的时间偏差，单位：秒
                'iss' => 'gaara',
            ],
        ],
    ]
];
