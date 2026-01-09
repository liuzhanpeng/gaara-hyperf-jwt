<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use Psr\Container\ContainerInterface;

/**
 * Refresh Token 管理器解析器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class RefreshTokenManagerResolver implements RefreshTokenManagerResolverInterface
{
    /**
     * @param array $refreshTokenManagerMap
     * @param ContainerInterface $container
     */
    public function __construct(
        private array $refreshTokenManagerMap,
        private ContainerInterface $container,
    ) {}

    /**
     * @inheritDoc
     */
    public function resolve(string $name = 'default'): RefreshTokenManagerInterface
    {
        if (!isset($this->refreshTokenManagerMap[$name])) {
            throw new \InvalidArgumentException("Refresh Token Manager does not exist: $name");
        }

        $refreshTokenManagerId = $this->refreshTokenManagerMap[$name];
        $refreshTokenManager = $this->container->get($refreshTokenManagerId);
        if (!$refreshTokenManager instanceof RefreshTokenManagerInterface) {
            throw new \LogicException(sprintf('Refresh Token Manager "%s" must implement %s interface', $refreshTokenManagerId, RefreshTokenManagerInterface::class));
        }

        return $refreshTokenManager;
    }
}
