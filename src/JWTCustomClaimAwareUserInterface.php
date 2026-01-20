<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

/**
 * 自定义JWT Claims用户接口
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
interface JWTCustomClaimAwareUserInterface
{
    /**
     * 返回自定义的JWT载荷声明集合
     *
     * @return array<string, mixed>
     */
    public function getJWTCustomClaims(): array;
}
