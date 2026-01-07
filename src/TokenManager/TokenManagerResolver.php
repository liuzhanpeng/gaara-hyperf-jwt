<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\TokenManager;

use Hyperf\Contract\ContainerInterface;

/**
 * Token管理器的解析器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class TokenManagerResolver implements TokenManagerResolverInterface
{
    /**
     * @param array $tokenManagerMap
     * @param ContainerInterface $container
     */
    public function __construct(
        private array $tokenManagerMap,
        private ContainerInterface $container,
    ) {}

    /**
     * @inheritDoc
     */
    public function resolve(string $name = 'default'): TokenManagerInterface
    {
        if (!isset($this->tokenManagerMap[$name])) {
            throw new \InvalidArgumentException("JWT Token Manager does not exist: $name");
        }

        $tokenManagerId = $this->tokenManagerMap[$name];
        $tokenManager = $this->container->get($tokenManagerId);
        if (!$tokenManager instanceof TokenManagerInterface) {
            throw new \LogicException(sprintf('JWT Token Manager "%s" must implement %s interface', $tokenManagerId, TokenManagerInterface::class));
        }

        return $tokenManager;
    }
}
