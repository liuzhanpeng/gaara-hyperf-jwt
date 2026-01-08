<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use Hyperf\Contract\ContainerInterface;

/**
 * AccessToken管理器的解析器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class AccessTokenManagerResolver implements AccessTokenManagerResolverInterface
{
    /**
     * @param array $accessTokenManagerMap
     * @param ContainerInterface $container
     */
    public function __construct(
        private array $accessTokenManagerMap,
        private ContainerInterface $container,
    ) {}

    /**
     * @inheritDoc
     */
    public function resolve(string $name = 'default'): AccessTokenManagerInterface
    {
        if (!isset($this->accessTokenManagerMap[$name])) {
            throw new \InvalidArgumentException("JWT Token Manager does not exist: $name");
        }

        $accessTokenManagerId = $this->accessTokenManagerMap[$name];
        $accessTokenManager = $this->container->get($accessTokenManagerId);
        if (!$accessTokenManager instanceof AccessTokenManagerInterface) {
            throw new \LogicException(sprintf('AccessToken Manager "%s" must implement %s interface', $accessTokenManagerId, AccessTokenManagerInterface::class));
        }

        return $accessTokenManager;
    }
}
