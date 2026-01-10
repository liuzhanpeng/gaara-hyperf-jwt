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
                return $this->container->make(AccessTokenManager::class, [
                    'algo' => $config['algo'] ?? 'HS512',
                    'secretKey' => $config['secret_key'] ?? '',
                    'publicKey' => $config['public_key'] ?? null,
                    'passphrase' => $config['passphrase'] ?? '',
                    'expiresIn' => $config['expires_in'] ?? 600,
                    'leeway' => $config['leeway'] ?? null,
                    'iss' => $config['iss'] ?? 'gaara-hyperf-jwt',
                    'aud' => $config['aud'] ?? '',
                ]);
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
