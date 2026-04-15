<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenIssuer;

use InvalidArgumentException;

/**
 * AccessToken发行器的解析器.
 */
class AccessTokenIssuerResolver implements AccessTokenIssuerResolverInterface
{
    private array $accessTokenIssuers = [];

    public function __construct(
        private array $factories,
    ) {
    }

    public function resolve(string $name = 'default'): AccessTokenIssuerInterface
    {
        if (! isset($this->accessTokenIssuers[$name])) {
            if (! isset($this->factories[$name])) {
                throw new InvalidArgumentException(sprintf('AccessToken Issuer "%s" is not defined', $name));
            }

            $this->accessTokenIssuers[$name] = ($this->factories[$name])();
        }

        return $this->accessTokenIssuers[$name];
    }
}
