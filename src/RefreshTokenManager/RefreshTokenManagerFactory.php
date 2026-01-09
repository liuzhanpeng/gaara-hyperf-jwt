<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use GaaraHyperf\Config\CustomConfig;
use GaaraHyperf\JWT\RefreshToken;
use Hyperf\Contract\ContainerInterface;

/**
 * RefreshToken管理创建工厂
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class RefreshTokenManagerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {}

    /**
     * @param array $config
     * @return RefreshTokenManagerInterface
     */
    public function create(array $config): RefreshTokenManagerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                return $this->container->make(RefreshTokenManager::class, [
                    'prefix' => $config['prefix'],
                    'expiresIn' => $config['expires_in'],
                    'singleSession' => $config['single_session'] ?? false,
                    'refreshTokenLength' => $config['refresh_token_length'],
                ]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $refreshTokenManager = $this->container->make($customConfig->class(), $customConfig->params());
                if (!$refreshTokenManager instanceof RefreshTokenManagerInterface) {
                    throw new \LogicException(sprintf('The custom RefreshTokenManager must implement %s.', RefreshTokenManagerInterface::class));
                }

                return $refreshTokenManager;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported refresh token manager type: %s', $type));
        }
    }
}
