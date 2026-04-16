<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\RefreshTokenIssuer;

use GaaraHyperf\Config\CustomConfig;
use GaaraHyperf\Constants;
use Hyperf\Contract\ContainerInterface;
use InvalidArgumentException;

/**
 * RefreshToken发行器创建工厂
 */
class RefreshTokenIssuerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {
    }

    public function create(array $config): RefreshTokenIssuerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                return $this->container->make(RefreshTokenIssuer::class, [
                    'prefix' => sprintf('%s:jwt_refresh_token:%s', Constants::__PREFIX, $config['prefix'] ?? 'default'),
                    'ttl' => $config['refresh_token_ttl'] ?? (60 * 60 * 24 * 14),
                    'singleSession' => $config['single_session'] ?? true,
                    'refreshTokenLength' => $config['refresh_token_length'] ?? 64,
                ]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $refreshTokenIssuer = $this->container->make($customConfig->class(), $customConfig->params());
                if (! $refreshTokenIssuer instanceof RefreshTokenIssuerInterface) {
                    throw new InvalidArgumentException(sprintf('The custom RefreshTokenIssuer must implement %s.', RefreshTokenIssuerInterface::class));
                }

                return $refreshTokenIssuer;
            default:
                throw new InvalidArgumentException(sprintf('Unsupported refresh token issuer type: %s', $type));
        }
    }
}
