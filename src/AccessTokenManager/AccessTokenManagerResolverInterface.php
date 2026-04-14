<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

/**
 * AccessToken管理器的解析器接口.
 */
interface AccessTokenManagerResolverInterface
{
    public function resolve(string $name = 'default'): AccessTokenManagerInterface;
}
