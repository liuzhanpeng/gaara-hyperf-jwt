<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\Constants;
use GaaraHyperf\JWT\TokenManager\TokenManagerFactory;
use GaaraHyperf\JWT\TokenManager\TokenManagerResolver;
use GaaraHyperf\JWT\TokenManager\TokenManagerResolverInterface;
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

        $tokenManagerCofing = array_merge([
            'default' => []
        ], $config->serviceConfig('jwt_token_managers') ?? []);

        $tokenManagerMap = [];
        foreach ($tokenManagerCofing as $name => $config) {
            $tokenManagerMap[$name] = sprintf('%s.%s.%s', Constants::__PREFIX, 'token_managers', $name);
            $container->define($tokenManagerMap[$name], fn() => $container->get(TokenManagerFactory::class)->create($config));
        }

        $container->define(TokenManagerResolverInterface::class, fn() => new TokenManagerResolver($tokenManagerMap, $container));

        $authenticatorFactory = $container->get(AuthenticatorFactory::class);
        $authenticatorFactory->registerBuilder('jwt', JWTAuthenticatorBuilder::class);
    }
}
