<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

/**
 * 刷新令牌
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class RefreshToken
{
    /**
     * @param string $token
     * @param integer $expiresIn
     */
    public function __construct(
        private string $token,
        private int $expiresIn,
    ) {}

    /**
     * 返回Token字符串
     * 
     * @return string
     */
    public function token(): string
    {
        return $this->token;
    }

    /**
     * 返回过期时间，单位：秒
     *
     * @return integer
     */
    public function expiresIn(): int
    {
        return $this->expiresIn;
    }
}
