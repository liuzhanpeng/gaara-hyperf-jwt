<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenManager;

use GaaraHyperf\Config\CustomConfig;
use Hyperf\Contract\ContainerInterface;

/**
 * AccessToken管理创建工厂
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class AccessTokenManagerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {}

    /**
     * @param array $config
     * @return AccessTokenManagerInterface
     */
    public function create(array $config): AccessTokenManagerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                if (!isset($config['secret_key']) || empty($config['secret_key'])) {
                    throw new \InvalidArgumentException('Missing secret key');
                }

                return $this->container->make(AccessTokenManager::class, ['options' => $config]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $accessTokenManager = $this->container->make($customConfig->class(), $customConfig->params());
                if (!$accessTokenManager instanceof AccessTokenManagerInterface) {
                    throw new \LogicException(sprintf('The custom AccessTokenManager must implement %s.', AccessTokenManagerInterface::class));
                }

                return $accessTokenManager;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported access token manager type: %s', $type));
        }
    }
}
