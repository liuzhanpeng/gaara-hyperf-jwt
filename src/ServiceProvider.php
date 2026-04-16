<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorFactory;
use GaaraHyperf\Authenticator\AuthenticatorFactory;
use GaaraHyperf\Config\ConfigLoaderInterface;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerFactory;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerResolver;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerResolverInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManager;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolver;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolverInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderFactory;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerFactory;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerResolver;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerResolverInterface;
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

        $configGroup = $gaaraConfig->serviceConfig('jwt_managers') + [
            'default' => [
            ],
        ];

        $accessTokenIssuerFactories = [];
        $refreshTokenIssuerFactories = [];
        $jwtManagerFactories = [];
        foreach ($configGroup as $name => $config) {
            $accessTokenIssuerFactories[$name] = fn () => $container->get(AccessTokenIssuerFactory::class)->create($config);
            $refreshTokenIssuerFactories[$name] = fn () => $container->get(RefreshTokenIssuerFactory::class)->create($config);

            $accessTokenExtractor = $container->get(AccessTokenExtractorFactory::class)->create(
                ($config['access_token_extractor'] ?? []) + [
                    'type' => 'header',
                    'field' => 'Authorization',
                ]
            );

            $refreshTokenExtractor = $container->get(AccessTokenExtractorFactory::class)->create(
                ($config['refresh_token_extractor'] ?? []) + [
                    'type' => 'body',
                    'field' => 'refresh_token',
                ]
            );

            $responder = $container->get(JWTokenResponderFactory::class)->create(
                ($config['token_responder'] ?? []) + [
                    'type' => 'body',
                    'template' => '{"code": 0, "message": "success", "data": {"access_token": "#ACCESS_TOKEN#", "expires_in": #EXPIRES_IN#, "refresh_token": "#REFRESH_TOKEN#", "refresh_token_expires_in": #REFRESH_EXPIRES_IN#}}',
                ]
            );

            $jwtManagerFactories[$name] = fn () => new JWTokenManager(
                accessTokenExtractor: $accessTokenExtractor,
                accessTokenIssuer: $container->get(AccessTokenIssuerResolverInterface::class)->resolve($name),
                responder: $responder,
                isRefreshTokenEnabled: $config['refresh_token_enabled'] ?? true,
                refreshTokenPath: $config['refresh_token_path'] ?? '',
                logoutPath: $config['logout_path'] ?? '',
                refreshTokenExtractor: $refreshTokenExtractor,
                refreshTokenIssuer: $container->get(RefreshTokenIssuerResolverInterface::class)->resolve($name),
            );
        }
        $container->set(AccessTokenIssuerResolverInterface::class, new AccessTokenIssuerResolver($accessTokenIssuerFactories));
        $container->set(RefreshTokenIssuerResolverInterface::class, new RefreshTokenIssuerResolver($refreshTokenIssuerFactories));
        $container->set(JWTokenManagerResolverInterface::class, new JWTokenManagerResolver($jwtManagerFactories));

        $authenticatorFactory = $container->get(AuthenticatorFactory::class);
        $authenticatorFactory->registerBuilder('jwt', JWTAuthenticatorBuilder::class);
    }
}
