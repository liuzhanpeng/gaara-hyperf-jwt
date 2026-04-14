<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenManager;

use GaaraHyperf\Config\CustomConfig;
use GaaraHyperf\Constants;
use Hyperf\Contract\ContainerInterface;
use InvalidArgumentException;

/**
 * RefreshToken管理创建工厂
 */
class RefreshTokenManagerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {
    }

    public function create(array $config): RefreshTokenManagerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                return $this->container->make(RefreshTokenManager::class, [
                    'prefix' => sprintf('%s:jwt_refresh_token:%s', Constants::__PREFIX, $config['prefix'] ?? 'default'),
                    'ttl' => $config['ttl'] ?? (60 * 60 * 24 * 14),
                    'singleSession' => $config['single_session'] ?? false,
                    'refreshTokenLength' => $config['refresh_token_length'] ?? 64,
                ]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $refreshTokenManager = $this->container->make($customConfig->class(), $customConfig->params());
                if (! $refreshTokenManager instanceof RefreshTokenManagerInterface) {
                    throw new InvalidArgumentException(sprintf('The custom RefreshTokenManager must implement %s.', RefreshTokenManagerInterface::class));
                }

                return $refreshTokenManager;
            default:
                throw new InvalidArgumentException(sprintf('Unsupported refresh token manager type: %s', $type));
        }
    }
}
