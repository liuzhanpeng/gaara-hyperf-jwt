<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

/**
 * 刷新令牌.
 */
class RefreshToken
{
    public function __construct(
        private string $token,
        private int $expiresIn,
    ) {
    }

    /**
     * 返回Token字符串.
     */
    public function token(): string
    {
        return $this->token;
    }

    /**
     * 返回过期时间，单位：秒.
     */
    public function expiresIn(): int
    {
        return $this->expiresIn;
    }
}
