<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\AccessTokenIssuer;

use GaaraHyperf\Config\CustomConfig;
use Hyperf\Contract\ContainerInterface;
use InvalidArgumentException;

/**
 * AccessToken发行器创建工厂
 */
class AccessTokenIssuerFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {
    }

    public function create(array $config): AccessTokenIssuerInterface
    {
        $type = $config['type'] ?? 'default';
        unset($config['type']);

        switch ($type) {
            case 'default':
                return $this->container->make(AccessTokenIssuer::class, [
                    'algo' => $config['algo'] ?? 'HS512',
                    'secretKey' => $config['secret_key'] ?? '',
                    'publicKey' => $config['public_key'] ?? null,
                    'passphrase' => $config['passphrase'] ?? '',
                    'ttl' => $config['ttl'] ?? 600,
                    'leeway' => $config['leeway'] ?? null,
                    'iss' => $config['iss'] ?? 'gaara-hyperf-jwt',
                    'aud' => $config['aud'] ?? '',
                ]);
            case 'custom':
                $customConfig = CustomConfig::from($config);

                $accessTokenIssuer = $this->container->make($customConfig->class(), $customConfig->params());
                if (! $accessTokenIssuer instanceof AccessTokenIssuerInterface) {
                    throw new InvalidArgumentException(sprintf('The custom AccessTokenIssuer must implement %s.', AccessTokenIssuerInterface::class));
                }

                return $accessTokenIssuer;
            default:
                throw new InvalidArgumentException(sprintf('Unsupported access token issuer type: %s', $type));
        }
    }
}
