<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\Constants;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerFactory;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolver;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerFactory;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolver;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\ServiceProvider\ServiceProviderInterface;
use Hyperf\Contract\ContainerInterface;

/**
 * 服务提供器
 * 
 * - 注入Token签发器
 * - 注册JWT认证器构建器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class ServiceProvider implements ServiceProviderInterface
{
    /**
     * @inheritDoc
     */
    public function register(ContainerInterface $container): void
    {
        $gaaraConfig = $container->get(ConfigLoaderInterface::class)->load();

        $accessTokenManagerConfig = array_replace_recursive([
            'default' => [
                'type' => 'default',
                'algo' => 'HS512',
                'ttl' => 600,
                'iss' => 'gaara-hyperf-jwt',
                'aud' => ''
            ]
        ], $gaaraConfig->serviceConfig('jwt_access_token_managers') ?? []);

        $accessTokenManagerMap = [];
        foreach ($accessTokenManagerConfig as $name => $config) {
            $accessTokenManagerMap[$name] = sprintf('%s.%s.%s', Constants::__PREFIX, 'jwt_access_token_managers', $name);
            $container->define($accessTokenManagerMap[$name], fn() => $container->get(AccessTokenManagerFactory::class)->create($config));
        }

        $container->define(AccessTokenManagerResolverInterface::class, fn() => new AccessTokenManagerResolver($accessTokenManagerMap, $container));

        $refreshTokenManagerConfig = array_replace_recursive([
            'default' => [
                'type' => 'default',
                'prefix' => 'default',
                'ttl' => 60 * 60 * 24 * 14,
                'single_session' => false,
                'refresh_token_length' => 64,
            ]
        ], $gaaraConfig->serviceConfig('jwt_refresh_token_managers') ?? []);

        $refreshTokenManagerMap = [];
        foreach ($refreshTokenManagerConfig as $name => $config) {
            $refreshTokenManagerMap[$name] = sprintf('%s.%s.%s', Constants::__PREFIX, 'jwt_refresh_token_managers', $name);
            $container->define($refreshTokenManagerMap[$name], fn() => $container->get(RefreshTokenManagerFactory::class)->create($config));
        }

        $container->define(RefreshTokenManagerResolverInterface::class, fn() => new RefreshTokenManagerResolver($refreshTokenManagerMap, $container));

        $authenticatorFactory = $container->get(AuthenticatorFactory::class);
        $authenticatorFactory->registerBuilder('jwt', JWTAuthenticatorBuilder::class);
    }
}
