<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

/**
 * Refresh Token 管理器解析器接口.
 */
interface RefreshTokenManagerResolverInterface
{
    public function resolve(string $name = 'default'): RefreshTokenManagerInterface;
}
