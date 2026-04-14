<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use InvalidArgumentException;

/**
 * Refresh Token 管理器解析器.
 */
class RefreshTokenManagerResolver implements RefreshTokenManagerResolverInterface
{
    private array $refreshTokenManagers = [];

    public function __construct(
        private array $factories,
    ) {
    }

    public function resolve(string $name = 'default'): RefreshTokenManagerInterface
    {
        if (! isset($this->refreshTokenManagers[$name])) {
            if (! isset($this->factories[$name])) {
                throw new InvalidArgumentException(sprintf('RefreshToken Manager "%s" is not defined', $name));
            }

            $this->refreshTokenManagers[$name] = ($this->factories[$name])();
        }

        return $this->refreshTokenManagers[$name];
    }
}
