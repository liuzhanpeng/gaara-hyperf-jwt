<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\User\UserInterface;

/**
 * JWT认证用户
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTUser implements UserInterface
{
    /**
     * @param string $identifier 用户唯一标识符
     * @param array $attributes 用户属性集合
     */
    public function __construct(
        private string $identifier,
        private array $attributes
    ) {}

    /**
     * @inheritDoc
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * 返回用户属性集合
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }
}
