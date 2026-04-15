<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenIssuer;

/**
 * Refresh Token 发行器解析器接口.
 */
interface RefreshTokenIssuerResolverInterface
{
    public function resolve(string $name = 'default'): RefreshTokenIssuerInterface;
}
