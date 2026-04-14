<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use InvalidArgumentException;

/**
 * AccessToken管理器的解析器.
 */
class AccessTokenManagerResolver implements AccessTokenManagerResolverInterface
{
    private array $accessTokenManagers = [];

    public function __construct(
        private array $factories,
    ) {
    }

    public function resolve(string $name = 'default'): AccessTokenManagerInterface
    {
        if (! isset($this->accessTokenManagers[$name])) {
            if (! isset($this->factories[$name])) {
                throw new InvalidArgumentException(sprintf('AccessToken Manager "%s" is not defined', $name));
            }

            $this->accessTokenManagers[$name] = ($this->factories[$name])();
        }

        return $this->accessTokenManagers[$name];
    }
}
