<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenIssuer;

use InvalidArgumentException;

/**
 * Refresh Token 发行器解析器.
 */
class RefreshTokenIssuerResolver implements RefreshTokenIssuerResolverInterface
{
    private array $refreshTokenIssuers = [];

    public function __construct(
        private array $factories,
    ) {
    }

    public function resolve(string $name = 'default'): RefreshTokenIssuerInterface
    {
        if (! isset($this->refreshTokenIssuers[$name])) {
            if (! isset($this->factories[$name])) {
                throw new InvalidArgumentException(sprintf('RefreshToken Issuer "%s" is not defined', $name));
            }

            $this->refreshTokenIssuers[$name] = ($this->factories[$name])();
        }

        return $this->refreshTokenIssuers[$name];
    }
}
