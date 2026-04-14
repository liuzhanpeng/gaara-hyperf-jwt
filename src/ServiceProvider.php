<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerFactory;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolver;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerFactory;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolver;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\ServiceProvider\ServiceProviderInterface;
use Hyperf\Contract\ContainerInterface;

/**
 * 服务提供器.
 *
 * - 注入Token/RefreshToken签发器
 * - 注册JWT认证器构建器
 */
class ServiceProvider implements ServiceProviderInterface
{
    public function register(ContainerInterface $container): void
    {
        $gaaraConfig = $container->get(ConfigLoaderInterface::class)->load();

        $accessTokenManagerConfig = $gaaraConfig->serviceConfig('jwt_access_token_managers') + [
            'default' => [
                'type' => 'default',
                'algo' => 'HS512',
                'ttl' => 600,
                'iss' => 'gaara-hyperf-jwt',
                'aud' => '',
            ],
        ];

        $accessTokenManagerfactories = [];
        foreach ($accessTokenManagerConfig as $name => $config) {
            $accessTokenManagerfactories[$name] = fn () => fn () => $container->get(AccessTokenManagerFactory::class)->create($config);
        }
        $container->define(AccessTokenManagerResolverInterface::class, fn () => new AccessTokenManagerResolver($accessTokenManagerfactories));

        $refreshTokenManagerConfig = $gaaraConfig->serviceConfig('jwt_refresh_token_managers') + [
            'default' => [
                'type' => 'default',
                'prefix' => 'default',
                'ttl' => 60 * 60 * 24 * 14,
                'single_session' => false,
                'refresh_token_length' => 64,
            ],
        ];
        $refreshTokenManagerFactories = [];
        foreach ($refreshTokenManagerConfig as $name => $config) {
            $refreshTokenManagerFactories[$name] = fn () => $container->get(RefreshTokenManagerFactory::class)->create($config);
        }
        $container->define(RefreshTokenManagerResolverInterface::class, fn () => new RefreshTokenManagerResolver($refreshTokenManagerFactories));

        $authenticatorFactory = $container->get(AuthenticatorFactory::class);
        $authenticatorFactory->registerBuilder('jwt', JWTAuthenticatorBuilder::class);
    }
}
