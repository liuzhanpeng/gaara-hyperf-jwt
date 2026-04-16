<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager;

/**
 * JWT Issuer解析器接口.
 */
interface JWTokenManagerResolverInterface
{
    public function resolve(string $name = 'default'): JWTokenManagerInterface;
}
