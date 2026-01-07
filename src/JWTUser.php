<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\JWT\TokenManager\JWToken;
use GaaraHyperf\User\UserInterface;

/**
 * JWT认证用户
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTUser implements UserInterface
{
    public function __construct(private JWToken $jwtoken) {}

    /**
     * @inheritDoc
     */
    public function getIdentifier(): string
    {
        return $this->jwtoken->sub();
    }

    /**
     * 返回用户属性集合
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->jwtoken->customClaims();
    }
}
