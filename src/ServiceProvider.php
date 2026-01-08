<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\Constants;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerFactory;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolver;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
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
    public function register(ContainerInterface $container): void
    {
        $config = $container->get(ConfigLoaderInterface::class)->load();

        $accessTokenManagerConfig = array_merge([
            'default' => [
                'type' => 'default',
                'algo' => 'HS512',
                'ttl' => 600,
                'iss' => 'gaara-hyperf-jwt',
                'aud' => 'gaara-hyperf-app',
            ]
        ], $config->serviceConfig('jwt_access_token_managers') ?? []);

        $accessTokenManagerMap = [];
        foreach ($accessTokenManagerConfig as $name => $config) {
            $accessTokenManagerMap[$name] = sprintf('%s.%s.%s', Constants::__PREFIX, 'jwt_access_token_managers', $name);
            $container->define($accessTokenManagerMap[$name], fn() => $container->get(AccessTokenManagerFactory::class)->create($config));
        }

        $container->define(AccessTokenManagerResolverInterface::class, fn() => new AccessTokenManagerResolver($accessTokenManagerMap, $container));

        $authenticatorFactory = $container->get(AuthenticatorFactory::class);
        $authenticatorFactory->registerBuilder('jwt', JWTAuthenticatorBuilder::class);
    }
}
