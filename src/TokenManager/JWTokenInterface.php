<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

/**
 * 令牌接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface JWTokenInterface
{
    /**
     * 返回签发方
     *
     * @return string
     */
    public function iss(): string;

    /**
     * 返回主体标识(User Identifier)
     *
     * @return string
     */
    public function sub(): string;

    /**
     * 返回受众
     *
     * @return string|null
     */
    public function aud(): ?string;

    /**
     * 返回签发时间
     *
     * @return integer
     */
    public function iat(): int;

    /**
     * 返回过期时间
     *
     * @return integer
     */
    public function exp(): int;

    /**
     * 返回之前无效时间
     *
     * @return integer|null
     */
    public function nbf(): ?int;

    /**
     * 返回唯一标识
     *
     * @return string
     */
    public function jti(): string;

    /**
     * 返回自己定义claims
     *
     * @return array
     */
    public function customClaims(): array;
}
