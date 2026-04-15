<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenIssuer;

/**
 * AccessToken发行器的解析器接口.
 */
interface AccessTokenIssuerResolverInterface
{
    public function resolve(string $name = 'default'): AccessTokenIssuerInterface;
}
