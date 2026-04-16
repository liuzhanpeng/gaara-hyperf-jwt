<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\JWTokenManager;

use InvalidArgumentException;

/**
 * JWTokenManager的解析器.
 */
class JWTokenManagerResolver implements JWTokenManagerResolverInterface
{
    private array $jwtManagers = [];

    public function __construct(
        private array $factories,
    ) {
    }

    public function resolve(string $name = 'default'): JWTokenManagerInterface
    {
        if (! isset($this->jwtManagers[$name])) {
            if (! isset($this->factories[$name])) {
                throw new InvalidArgumentException(sprintf('JWTokenManager "%s" is not defined', $name));
            }

            $this->jwtManagers[$name] = ($this->factories[$name])();
        }

        return $this->jwtManagers[$name];
    }
}
